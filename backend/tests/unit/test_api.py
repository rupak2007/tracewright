"""HTTP API over a SQLite database seeded with a synthetic analysis (tests/db_helpers.py)."""

import gzip
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.api.main import create_app
from app.core.config import get_api_settings, get_settings
from app.db.models import (
    EvidenceRecord,
    Feedback,
    Finding,
    Incident,
    Investigation,
    Job,
    SliceRow,
)
from tests.db_helpers import PCAP_HEADER, REPO, app_settings, make_engine, seed_completed


@dataclass
class World:
    client: TestClient
    engine: Engine
    tmp: Path
    uploads: Path
    artifacts: Path
    investigation: str


def make_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **env: str) -> Iterator[World]:
    uploads, artifacts = tmp_path / "uploads", tmp_path / "artifacts"
    uploads.mkdir()
    artifacts.mkdir()
    values = {
        "POSTGRES_DB": "tw",
        "POSTGRES_USER": "u",
        "POSTGRES_PASSWORD": "p",
        "UPLOADS_DIR": str(uploads),
        "ARTIFACTS_DIR": str(artifacts),
        "CONFIG_DIR": str(REPO / "config"),
        "KNOWLEDGE_DIR": str(REPO / "knowledge"),
        **env,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    get_api_settings.cache_clear()
    engine = make_engine()
    inv = seed_completed(engine, app_settings(tmp_path))
    with TestClient(create_app(engine), raise_server_exceptions=False) as client:
        yield World(client, engine, tmp_path, uploads, artifacts, inv)


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    yield from make_world(tmp_path, monkeypatch)


def post_file(
    w: World, content: bytes, name: str = "x.pcap", field: str = "file", **kw: Any
) -> Any:
    return w.client.post("/api/v1/investigations", files={field: (name, content)}, **kw)


def first_finding_id(w: World, kind: str | None = None) -> int:
    with Session(w.engine) as s:
        query = select(Finding.id).order_by(Finding.id)
        if kind:
            query = query.where(Finding.type == kind)
        return int(s.scalars(query).first() or 0)


# ---- error format, auth, CORS, docs -----------------------------------------------------
def test_unknown_route_and_validation_errors_use_the_documented_error_shape(world: World) -> None:
    r = world.client.get("/api/v1/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"
    r = world.client.get("/api/v1/incidents/not-a-number")
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"
    r = world.client.get("/api/v1/investigations/does-not-exist")
    assert r.status_code == 404 and set(r.json()) == {"error"}


def test_unhandled_errors_never_leak_their_text(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.investigations as inv_module

    def boom(*_: object, **__: object) -> None:
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(inv_module, "_summary", boom)
    r = world.client.get("/api/v1/investigations")
    assert r.status_code == 500 and r.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "secret" not in r.text


def test_bearer_token_protects_everything_but_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for w in make_world(tmp_path, monkeypatch, API_TOKEN="s3cret-token"):  # noqa: S106
        assert w.client.get("/api/v1/health").status_code == 200
        assert w.client.get("/api/v1/investigations").status_code == 401
        bad = {"Authorization": "Bearer wrong"}
        assert w.client.get("/api/v1/investigations", headers=bad).status_code == 401
        assert (
            w.client.get(
                "/api/v1/investigations", headers={"Authorization": "Basic s3cret-token"}
            ).status_code
            == 401
        )
        ok = {"Authorization": "Bearer s3cret-token"}
        assert w.client.get("/api/v1/investigations", headers=ok).status_code == 200
        assert (
            w.client.get(f"/api/v1/investigations/{w.investigation}", headers=ok).status_code == 200
        )
        assert (
            w.client.post(
                "/api/v1/findings/1/feedback", json={"label": "true_positive"}
            ).status_code
            == 401
        )


def test_cors_allows_only_the_configured_ui_origins(world: World) -> None:
    allowed = world.client.options(
        "/api/v1/investigations",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    other = world.client.options(
        "/api/v1/investigations",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in other.headers


def test_every_documented_endpoint_exists_in_the_openapi_schema(world: World) -> None:
    schema = world.client.get("/openapi.json").json()
    expected = {
        ("post", "/api/v1/investigations"),
        ("get", "/api/v1/investigations"),
        ("get", "/api/v1/investigations/{investigation_id}"),
        ("delete", "/api/v1/investigations/{investigation_id}"),
        ("get", "/api/v1/investigations/{investigation_id}/incidents"),
        ("get", "/api/v1/investigations/{investigation_id}/anomalies"),
        ("get", "/api/v1/incidents/{incident_id}"),
        ("get", "/api/v1/incidents/{incident_id}/evidence"),
        ("get", "/api/v1/incidents/{incident_id}/report"),
        ("post", "/api/v1/findings/{finding_id}/slice"),
        ("get", "/api/v1/slices/{slice_id}"),
        ("get", "/api/v1/slices/{slice_id}/download"),
        ("post", "/api/v1/findings/{finding_id}/feedback"),
        ("get", "/api/v1/config/network"),
        ("get", "/api/v1/health"),
    }
    present = {(m, p) for p, ops in schema["paths"].items() for m in ops}
    assert expected <= present


# ---- upload -----------------------------------------------------------------------------
def test_valid_upload_is_stored_under_a_uuid_name_and_queued(world: World) -> None:
    r = post_file(world, PCAP_HEADER, name="../../etc/evil.pcap")
    assert r.status_code == 202 and r.json()["status"] == "queued"
    inv_id = r.json()["id"]
    assert (world.uploads / f"{inv_id}.pcap").read_bytes() == PCAP_HEADER
    assert [p.name for p in world.uploads.iterdir() if p.suffix != ".pcap"] == []  # no .part left
    with Session(world.engine) as s:
        inv = s.get(Investigation, inv_id)
        assert inv is not None and inv.original_name == "evil.pcap"  # directory parts dropped
        assert inv.upload_name == f"{inv_id}.pcap" and len(inv.sha256) == 64
        jobs = s.scalars(select(Job).where(Job.investigation_id == inv_id)).all()
        assert [(j.type, j.status) for j in jobs] == [("analyze", "queued")]
    assert not (world.tmp / "etc").exists() and not (world.uploads.parent / "evil.pcap").exists()


@pytest.mark.parametrize(
    ("content", "status", "code"),
    [
        (b"MZ this is not a capture", 415, "FILE_TYPE_INVALID"),
        (gzip.compress(PCAP_HEADER), 415, "FILE_COMPRESSED"),
        (b"", 400, "FILE_EMPTY"),
    ],
)
def test_bad_uploads_are_rejected_and_leave_nothing_behind(
    world: World, content: bytes, status: int, code: str
) -> None:
    before = set(world.uploads.iterdir())
    r = post_file(world, content)
    assert r.status_code == status and r.json()["error"]["code"] == code
    assert set(world.uploads.iterdir()) == before


def test_oversize_upload_is_cut_off_while_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for w in make_world(tmp_path, monkeypatch, MAX_UPLOAD_BYTES="100"):
        before = set(w.uploads.iterdir())
        r = post_file(w, PCAP_HEADER + b"\x00" * 500)
        assert r.status_code == 413 and r.json()["error"]["code"] == "FILE_TOO_LARGE"
        assert set(w.uploads.iterdir()) == before


def test_upload_needs_a_multipart_request_with_a_file_part(world: World) -> None:
    r = world.client.post("/api/v1/investigations", content=PCAP_HEADER)
    assert r.status_code == 415 and r.json()["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"
    r = post_file(world, PCAP_HEADER, field="not_file")
    assert r.status_code == 400 and r.json()["error"]["code"] == "NO_FILE"


def test_extra_fields_and_a_second_file_are_ignored(world: World) -> None:
    r = world.client.post(
        "/api/v1/investigations",
        data={"note": "hello"},
        files=[("file", ("a.pcap", PCAP_HEADER)), ("file", ("b.pcap", b"MZ junk"))],
    )
    assert r.status_code == 202
    assert len([p for p in world.uploads.iterdir() if p.suffix == ".pcap"]) == 2  # seeded + new


# ---- investigations ---------------------------------------------------------------------
def test_list_and_read_investigations(world: World) -> None:
    listing = world.client.get("/api/v1/investigations").json()
    assert [i["id"] for i in listing] == [world.investigation] and listing[0]["incident_count"] == 4
    detail = world.client.get(f"/api/v1/investigations/{world.investigation}").json()
    assert detail["status"] == "completed" and detail["manifest"]["attack_version"] == "19.2"
    assert detail["profile"]["connections"] > 0 and "validate" in detail["stage_ms"]
    assert detail["profile"]["anomalies"]["status"] == "off"


def test_delete_removes_rows_files_and_derived_data(world: World) -> None:
    inv = world.investigation
    assert (world.uploads / f"{inv}.pcap").exists() and (world.artifacts / inv).is_dir()
    assert world.client.delete(f"/api/v1/investigations/{inv}").status_code == 204
    assert not (world.uploads / f"{inv}.pcap").exists() and not (world.artifacts / inv).exists()
    with Session(world.engine) as s:
        for model in (Investigation, Incident, Finding, EvidenceRecord, Job):
            assert s.scalar(select(func.count()).select_from(model)) == 0
    assert world.client.get(f"/api/v1/investigations/{inv}").status_code == 404
    assert world.client.delete(f"/api/v1/investigations/{inv}").status_code == 404


def test_a_running_investigation_cannot_be_deleted(world: World) -> None:
    with Session(world.engine) as s:
        inv = s.get(Investigation, world.investigation)
        assert inv is not None
        inv.status = "running"
        s.commit()
    r = world.client.delete(f"/api/v1/investigations/{world.investigation}")
    assert r.status_code == 409 and r.json()["error"]["code"] == "CONFLICT"


# ---- incidents, evidence, anomalies -----------------------------------------------------
def test_incidents_are_ranked_with_links(world: World) -> None:
    rows = world.client.get(f"/api/v1/investigations/{world.investigation}/incidents").json()
    assert [r["rank"] for r in rows] == [1, 2, 3, 4]
    scores = [r["severity_score"] for r in rows]
    assert scores == sorted(scores, reverse=True)
    assert {lk["type"] for r in rows for lk in r["links"]} == {
        "TARGET_LATER_ACTIVE",
        "SHARED_EXTERNAL_PEER",
    }
    assert all(r["finding_count"] >= 1 and r["types"] for r in rows)


def test_incident_detail_carries_findings_techniques_cards_playbooks_and_summary(
    world: World,
) -> None:
    rows = world.client.get(f"/api/v1/investigations/{world.investigation}/incidents").json()
    top = world.client.get(f"/api/v1/incidents/{rows[0]['id']}").json()
    assert top["local_id"] == rows[0]["local_id"] and "[E-" in top["summary"]
    f = top["findings"][0]
    assert f["metrics"] and f["thresholds"] and f["benign_causes"] and f["detector_version"]
    assert f["techniques"] and f["techniques"][0]["phrase"].startswith("consistent with")
    assert top["cards"] and top["cards"][0]["knowledge_id"].startswith("K-T")
    assert top["playbooks"] and top["playbooks"][0].startswith("K-PB-DET-")
    assert world.client.get("/api/v1/incidents/99999").status_code == 404


def test_evidence_is_paged_filtered_and_stable(world: World) -> None:
    rows = world.client.get(f"/api/v1/investigations/{world.investigation}/incidents").json()
    inc = next(r for r in rows if r["finding_count"] > 1 or r["types"] == ["BRUTE", "SCAN"])
    page = world.client.get(f"/api/v1/incidents/{inc['id']}/evidence?limit=5").json()
    assert page["limit"] == 5 and len(page["items"]) == 5 and page["total"] > 5
    assert [i["local_id"] for i in page["items"]] == ["E-1", "E-2", "E-3", "E-4", "E-5"]
    assert page["items"][0]["kind"] == "aggregate"
    nxt = world.client.get(f"/api/v1/incidents/{inc['id']}/evidence?limit=5&offset=5").json()
    assert nxt["items"][0]["local_id"] == "E-6" and nxt["total"] == page["total"]
    finding = world.client.get(f"/api/v1/incidents/{inc['id']}").json()["findings"][0]["id"]
    only = world.client.get(f"/api/v1/incidents/{inc['id']}/evidence?finding_id={finding}").json()
    assert 0 < only["total"] <= page["total"]
    assert {i["finding_id"] for i in only["items"]} == {finding}
    assert world.client.get(f"/api/v1/incidents/{inc['id']}/evidence?limit=0").status_code == 422
    assert world.client.get(f"/api/v1/incidents/{inc['id']}/evidence?limit=201").status_code == 422


def test_anomalies_endpoint_labels_results_as_unusual_not_malicious(world: World) -> None:
    body = world.client.get(f"/api/v1/investigations/{world.investigation}/anomalies").json()
    assert (
        body["summary"]["status"] == "off"
        and "unusual relative to this capture" in body["summary"]["label"]
    )
    assert body["scored_windows"] == [] and body["promoted_findings"] == []


# ---- reports ----------------------------------------------------------------------------
def test_reports_download_as_markdown_or_escaped_html(world: World) -> None:
    rows = world.client.get(f"/api/v1/investigations/{world.investigation}/incidents").json()
    tunnel = next(r for r in rows if r["types"] == ["DNSTUN"])
    md = world.client.get(f"/api/v1/incidents/{tunnel['id']}/report?format=md")
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert (
        "attachment" in md.headers["content-disposition"]
        and md.headers["x-content-type-options"] == "nosniff"
    )
    assert "\\<img" in md.text and "<img" not in md.text.replace("\\<img", "")  # escaped
    assert "## Run manifest" in md.text and "## Limitations" in md.text
    html = world.client.get(f"/api/v1/incidents/{tunnel['id']}/report?format=html")
    assert html.headers["content-type"].startswith("text/html")
    assert "&lt;img src=x onerror=alert(1)&gt;" in html.text and "<img" not in html.text
    assert "script-src &#x27;none&#x27;" in html.text and "<script" not in html.text
    assert (
        world.client.get(f"/api/v1/incidents/{tunnel['id']}/report?format=pdf").status_code == 422
    )


def test_reports_include_analyst_feedback(world: World) -> None:
    rows = world.client.get(f"/api/v1/investigations/{world.investigation}/incidents").json()
    detail = world.client.get(f"/api/v1/incidents/{rows[0]['id']}").json()
    fid = detail["findings"][0]["id"]
    world.client.post(
        f"/api/v1/findings/{fid}/feedback",
        json={"label": "expected_benign", "note": "backup <b>job</b>"},
    )
    md = world.client.get(f"/api/v1/incidents/{rows[0]['id']}/report?format=md").text
    assert "expected\\_benign" in md and "\\<b\\>job\\</b\\>" in md


# ---- feedback ---------------------------------------------------------------------------
def test_feedback_is_stored_and_listed_on_the_finding(world: World) -> None:
    fid = first_finding_id(world)
    r = world.client.post(
        f"/api/v1/findings/{fid}/feedback", json={"label": "false_positive", "note": "NTP"}
    )
    assert r.status_code == 201 and r.json()["label"] == "false_positive"
    rows = world.client.get(f"/api/v1/investigations/{world.investigation}/incidents").json()
    labels = [
        fb["label"]
        for row in rows
        for f in world.client.get(f"/api/v1/incidents/{row['id']}").json()["findings"]
        for fb in f["feedback"]
    ]
    assert labels == ["false_positive"]


def test_feedback_validation(world: World) -> None:
    fid = first_finding_id(world)
    assert (
        world.client.post(f"/api/v1/findings/{fid}/feedback", json={"label": "maybe"}).status_code
        == 422
    )
    assert (
        world.client.post(
            f"/api/v1/findings/{fid}/feedback", json={"label": "true_positive", "note": "x" * 2001}
        ).status_code
        == 422
    )
    assert (
        world.client.post(
            f"/api/v1/findings/{fid}/feedback", json={"label": "true_positive", "extra": 1}
        ).status_code
        == 422
    )
    assert (
        world.client.post(
            "/api/v1/findings/99999/feedback", json={"label": "true_positive"}
        ).status_code
        == 404
    )
    with Session(world.engine) as s:
        assert s.scalar(select(func.count()).select_from(Feedback)) == 0


# ---- slices (API side; the worker side is tested in test_worker_jobs) --------------------
def test_slice_request_queues_a_job_once_and_download_waits_for_the_worker(world: World) -> None:
    fid = first_finding_id(world, "BRUTE")
    r = world.client.post(f"/api/v1/findings/{fid}/slice")
    assert r.status_code == 202 and r.json()["status"] == "queued"
    slice_id = r.json()["slice_id"]
    assert world.client.post(f"/api/v1/findings/{fid}/slice").json()["slice_id"] == slice_id
    with Session(world.engine) as s:
        queued = s.scalars(select(Job).where(Job.type == "slice")).all()
        assert len(queued) == 1 and queued[0].params == {"slice_id": slice_id}
        assert s.scalar(select(func.count()).select_from(SliceRow)) == 1
    status = world.client.get(f"/api/v1/slices/{slice_id}").json()
    assert status["status"] == "queued" and status["size_bytes"] is None
    assert world.client.get(f"/api/v1/slices/{slice_id}/download").status_code == 409
    assert world.client.get("/api/v1/slices/999").status_code == 404
    assert world.client.post("/api/v1/findings/99999/slice").status_code == 404


def test_a_finished_slice_downloads_as_a_pcap_with_a_server_chosen_name(world: World) -> None:
    fid = first_finding_id(world, "BRUTE")
    slice_id = world.client.post(f"/api/v1/findings/{fid}/slice").json()["slice_id"]
    folder = world.artifacts / world.investigation / "slices"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{slice_id}.pcap").write_bytes(PCAP_HEADER)
    with Session(world.engine) as s:
        row = s.get(SliceRow, slice_id)
        assert row is not None
        row.status, row.filename, row.size_bytes, row.packets = "done", f"{slice_id}.pcap", 44, 1
        s.commit()
    r = world.client.get(f"/api/v1/slices/{slice_id}/download")
    assert r.status_code == 200 and r.content == PCAP_HEADER
    assert r.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert f"tracewright-slice-{slice_id}.pcap" in r.headers["content-disposition"]
    (folder / f"{slice_id}.pcap").unlink()
    assert world.client.get(f"/api/v1/slices/{slice_id}/download").status_code == 404


def test_slices_need_a_completed_analysis(world: World) -> None:
    fid = first_finding_id(world)
    with Session(world.engine) as s:
        inv = s.get(Investigation, world.investigation)
        assert inv is not None
        inv.status = "failed"
        s.commit()
    assert world.client.post(f"/api/v1/findings/{fid}/slice").status_code == 409


# ---- config and health ------------------------------------------------------------------
def test_network_config_is_readable(world: World) -> None:
    body = world.client.get("/api/v1/config/network").json()
    assert "10.0.0.0/8" in body["internal_cidrs"] and body["allowlist"]["periodic_ports"] == [123]


def test_health_reports_database_and_worker_heartbeat(world: World) -> None:
    assert world.client.get("/api/v1/health").json() == {
        "status": "ok",
        "db": "ok",
        "worker": "unknown",
    }
    from app.db import jobs

    with Session(world.engine) as s:
        jobs.beat(s, "w1")
        s.commit()
    assert world.client.get("/api/v1/health").json()["worker"] == "alive"
