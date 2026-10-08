"""Narrative endpoints over the seeded SYNTHETIC analysis, with scripted providers."""

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.narratives import default_client_factory
from app.db.models import Narrative
from app.explain.llm_client import LlmClient, LlmUnavailable, NoneClient
from tests.unit.test_api import World, make_world
from tests.unit.test_narrative import Scripted


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    yield from make_world(tmp_path, monkeypatch)


def incident_ids(w: World) -> list[int]:
    rows = w.client.get(f"/api/v1/investigations/{w.investigation}/incidents").json()
    return [r["id"] for r in rows]


def narrative_for(w: World, incident_id: int) -> dict[str, Any]:
    pack = w.client.get(f"/api/v1/incidents/{incident_id}").json()
    first = pack["findings"][0]
    return {
        "summary": "A pattern in this capture that deserves a closer look.",
        "observed": [
            {
                "statement": "One detector fired for this incident.",
                "evidence_ids": [first["local_id"]],
            }
        ],
        "inferences": [
            {
                "statement": "This could be routine automation.",
                "supporting_ids": [first["local_id"]],
                "knowledge_ids": [],
                "confidence": "low",
                "alternative_explanations": ["a scheduled job or a monitoring agent"],
            }
        ],
        "recommendations": [
            {"action": "Check the host's scheduled jobs.", "rationale_ids": [first["local_id"]]}
        ],
        "open_questions": ["Is this traffic expected in this network?"],
    }


def use(w: World, client: LlmClient) -> None:
    w.client.app.state.llm_client_factory = lambda: client  # type: ignore[attr-defined]


def test_not_requested_until_asked_and_the_default_provider_is_none(world: World) -> None:
    iid = incident_ids(world)[0]
    body = world.client.get(f"/api/v1/incidents/{iid}/narrative").json()
    assert body["status"] == "not_requested" and body["output"] is None
    assert body["provider"] == "none" and "analyst decides" in body["label"]
    assert isinstance(default_client_factory(), NoneClient)


def test_with_no_provider_the_narrative_is_unavailable_and_the_template_stays(
    world: World,
) -> None:
    iid = incident_ids(world)[0]
    posted = world.client.post(f"/api/v1/incidents/{iid}/narrative")
    assert posted.status_code == 202 and posted.json()["status"] == "pending"
    body = world.client.get(f"/api/v1/incidents/{iid}/narrative").json()
    assert body["status"] == "unavailable" and body["output"] is None and body["reasons"]
    detail = world.client.get(f"/api/v1/incidents/{iid}").json()
    assert "[E-" in detail["summary"]  # the template summary is untouched


def test_a_validated_narrative_is_returned_with_the_real_values_kept_separate(
    world: World,
) -> None:
    iid = incident_ids(world)[0]
    good = narrative_for(world, iid)
    use(world, Scripted(json.dumps(good)))
    assert world.client.post(f"/api/v1/incidents/{iid}/narrative").status_code == 202
    body = world.client.get(f"/api/v1/incidents/{iid}/narrative").json()
    assert body["status"] == "validated" and body["output"] == good
    assert (
        body["provider"] == "fake" and body["model"] == "fake-1" and len(body["prompt_hash"]) == 64
    )
    assert body["entities"] and set(body["entities"]) <= {*body["entities"]}
    assert all(k[0] in "HXD" for k in body["entities"])


def test_a_rejected_narrative_hides_the_text_but_keeps_it_for_evaluation(world: World) -> None:
    iid = incident_ids(world)[0]
    bad = {**narrative_for(world, iid), "summary": "This host is compromised."}
    use(world, Scripted(json.dumps(bad), json.dumps(bad)))
    world.client.post(f"/api/v1/incidents/{iid}/narrative")
    response = world.client.get(f"/api/v1/incidents/{iid}/narrative")
    body = response.json()
    assert body["status"] == "rejected" and body["output"] is None and body["reasons"]
    assert "This host is compromised." not in response.text  # the model's text is never shown
    assert "raw_output" not in body
    with Session(world.engine) as s:
        row = s.scalars(select(Narrative).where(Narrative.incident_id == iid)).one()
        assert row.status == "rejected" and "compromised" in (row.raw_output or "")


def test_a_provider_outage_is_unavailable(world: World) -> None:
    iid = incident_ids(world)[0]
    use(world, Scripted(LlmUnavailable("down")))
    world.client.post(f"/api/v1/incidents/{iid}/narrative")
    body = world.client.get(f"/api/v1/incidents/{iid}/narrative").json()
    assert body["status"] == "unavailable" and body["reasons"] == ["down"]


def test_a_generation_bug_degrades_to_unavailable_without_leaking_its_text(
    world: World,
) -> None:
    iid = incident_ids(world)[0]

    class Broken:
        provider, model = "broken", "b"

        def generate(self, system: str, user: str) -> str:
            raise RuntimeError("secret internal detail")

    use(world, Broken())
    world.client.post(f"/api/v1/incidents/{iid}/narrative")
    response = world.client.get(f"/api/v1/incidents/{iid}/narrative")
    assert response.json()["status"] == "unavailable"
    assert "secret internal detail" not in response.text


def test_regenerating_replaces_the_previous_result(world: World) -> None:
    iid = incident_ids(world)[0]
    use(world, Scripted(json.dumps(narrative_for(world, iid))))
    world.client.post(f"/api/v1/incidents/{iid}/narrative")
    use(world, Scripted(LlmUnavailable("later outage")))
    world.client.post(f"/api/v1/incidents/{iid}/narrative")
    body = world.client.get(f"/api/v1/incidents/{iid}/narrative").json()
    assert body["status"] == "unavailable" and body["output"] is None
    with Session(world.engine) as s:
        assert len(s.scalars(select(Narrative).where(Narrative.incident_id == iid)).all()) == 1


def test_unknown_incident_is_404(world: World) -> None:
    assert world.client.post("/api/v1/incidents/99999/narrative").status_code == 404
    assert world.client.get("/api/v1/incidents/99999/narrative").status_code == 404


def test_the_prompt_sent_to_the_provider_holds_no_real_value(world: World) -> None:
    iid = incident_ids(world)[0]
    client = Scripted(LlmUnavailable("stop"))
    use(world, client)
    world.client.post(f"/api/v1/incidents/{iid}/narrative")
    system, user = client.calls[0]
    assert not re.search(r"(?:\d{1,3}\.){3}\d{1,3}", user + system)  # no IPv4 address
    assert "Evidence pack" in user and re.search(r'"H1"', user)


def test_the_narrative_endpoints_need_the_bearer_token_when_one_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for w in make_world(tmp_path, monkeypatch, API_TOKEN="tok-123"):  # noqa: S106
        assert w.client.get("/api/v1/incidents/1/narrative").status_code == 401
        assert w.client.post("/api/v1/incidents/1/narrative").status_code == 401
        headers = {"Authorization": "Bearer tok-123"}
        assert w.client.get("/api/v1/incidents/1/narrative", headers=headers).status_code == 200


def test_a_validated_narrative_is_labelled_in_both_reports_and_a_rejected_one_is_absent(
    world: World,
) -> None:
    iid = incident_ids(world)[0]
    for fmt in ("md", "html"):
        plain = world.client.get(f"/api/v1/incidents/{iid}/report?format={fmt}").text
        assert "machine-generated" not in plain.lower().replace("machine-generated narrative", "")
        assert "Narrative (optional" not in plain
    good = narrative_for(world, iid)
    use(world, Scripted(json.dumps(good)))
    world.client.post(f"/api/v1/incidents/{iid}/narrative")
    md = world.client.get(f"/api/v1/incidents/{iid}/report?format=md").text
    assert "### Narrative (optional, machine-generated)" in md
    assert "validated against the evidence" in md and "analyst decides" in md
    assert "Inferences (hypotheses, not findings)" in md and "Could also be:" in md
    html = world.client.get(f"/api/v1/incidents/{iid}/report?format=html").text
    assert "Narrative (optional, machine-generated)" in html and "<img" not in html
    assert md.index("### Narrative") < md.index("### Findings")

    bad = {**good, "summary": "This host is compromised."}
    use(world, Scripted(json.dumps(bad), json.dumps(bad)))
    world.client.post(f"/api/v1/incidents/{iid}/narrative")
    md = world.client.get(f"/api/v1/incidents/{iid}/report?format=md").text
    assert "Narrative (optional" not in md and "compromised" not in md.lower()


def test_a_pending_narrative_that_outlived_its_task_is_reported_unavailable(world: World) -> None:
    """Regression (release audit): an API restart used to leave `pending` forever, and the UI
    disables its button while pending, so the analyst could never retry."""
    from datetime import timedelta

    from app.db.models import utcnow

    iid = incident_ids(world)[0]
    with Session(world.engine) as s:
        s.add(Narrative(incident_id=iid, status="pending", created_at=utcnow()))
        s.commit()
    fresh = world.client.get(f"/api/v1/incidents/{iid}/narrative").json()
    assert fresh["status"] == "pending"  # a recent request is still running
    with Session(world.engine) as s:
        row = s.scalars(select(Narrative).where(Narrative.incident_id == iid)).one()
        row.created_at = utcnow() - timedelta(hours=1)
        s.commit()
    stale = world.client.get(f"/api/v1/incidents/{iid}/narrative").json()
    assert stale["status"] == "unavailable" and "did not finish" in stale["reasons"][0]
    assert stale["output"] is None
    use(world, Scripted(json.dumps(narrative_for(world, iid))))
    assert world.client.post(f"/api/v1/incidents/{iid}/narrative").status_code == 202
    assert world.client.get(f"/api/v1/incidents/{iid}/narrative").json()["status"] == "validated"
