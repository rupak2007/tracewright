"""SEC-11 / FR-45: deleting an investigation removes every row and file derived from it.

Retention is manual by design (docs/SECURITY.md): nothing is deleted automatically, and `DELETE`
is the one way data leaves. This test seeds everything an investigation can accumulate (feedback,
a narrative, a finished slice and its file) and checks that none of it survives, while a second
investigation's data is untouched.
"""

import json
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    EvidenceRecord,
    Feedback,
    Finding,
    Incident,
    Investigation,
    Job,
    Narrative,
    SliceRow,
)
from tests.db_helpers import PCAP_HEADER, app_settings, seed_completed
from tests.unit.test_api import World, first_finding_id, make_world, post_file
from tests.unit.test_api_narrative import narrative_for, use
from tests.unit.test_narrative import Scripted

TABLES = (Investigation, Incident, Finding, EvidenceRecord, Job, Feedback, Narrative, SliceRow)


def counts(world: World) -> dict[str, int]:
    with Session(world.engine) as s:
        return {m.__name__: int(s.scalar(select(func.count()).select_from(m)) or 0) for m in TABLES}


def accumulate(world: World) -> int:
    """Feedback, a validated narrative and a finished slice on the seeded investigation."""
    client, inv = world.client, world.investigation
    fid = first_finding_id(world, "BRUTE")
    assert (
        client.post(
            f"/api/v1/findings/{fid}/feedback", json={"label": "false_positive", "note": "lab"}
        ).status_code
        == 201
    )
    incident = client.get(f"/api/v1/investigations/{inv}/incidents").json()[0]["id"]
    use(world, Scripted(json.dumps(narrative_for(world, incident))))
    client.post(f"/api/v1/incidents/{incident}/narrative")
    slice_id = client.post(f"/api/v1/findings/{fid}/slice").json()["slice_id"]
    folder = world.artifacts / inv / "slices"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{slice_id}.pcap").write_bytes(PCAP_HEADER)
    with Session(world.engine) as s:
        row = s.get(SliceRow, slice_id)
        assert row is not None
        row.status, row.filename = "done", f"{slice_id}.pcap"
        s.commit()
    return slice_id


def test_delete_removes_feedback_narratives_slices_and_every_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for world in make_world(tmp_path, monkeypatch):
        slice_id = accumulate(world)
        before = counts(world)
        assert before["Feedback"] == before["Narrative"] == before["SliceRow"] == 1
        inv = world.investigation
        assert world.client.delete(f"/api/v1/investigations/{inv}").status_code == 204
        assert all(n == 0 for n in counts(world).values()), counts(world)
        assert not list(world.uploads.iterdir()) and not list(world.artifacts.iterdir())
        assert world.client.get(f"/api/v1/slices/{slice_id}/download").status_code == 404
        assert world.client.get(f"/api/v1/investigations/{inv}").status_code == 404


def test_delete_leaves_a_second_investigation_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for world in make_world(tmp_path, monkeypatch):
        other = seed_completed(world.engine, app_settings(tmp_path))
        # the second seed shares the settings directories only through its own ids
        kept = {p.name for p in world.uploads.iterdir() if p.stem == other}
        assert (
            world.client.delete(f"/api/v1/investigations/{world.investigation}").status_code == 204
        )
        assert world.client.get(f"/api/v1/investigations/{other}").status_code == 200
        assert {p.name for p in world.uploads.iterdir() if p.stem == other} == kept


def test_an_uploaded_but_unanalysed_capture_is_deleted_with_its_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for world in make_world(tmp_path, monkeypatch):
        created = post_file(world, PCAP_HEADER).json()["id"]
        stored = [p for p in world.uploads.iterdir() if p.stem == created]
        assert len(stored) == 1
        assert world.client.delete(f"/api/v1/investigations/{created}").status_code == 204
        assert not [p for p in world.uploads.iterdir() if p.stem == created]
