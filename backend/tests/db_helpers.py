"""SYNTHETIC fixtures for the API/worker/persistence tests.

`seed_completed` runs the REAL pipeline stages on the storyline evidence of
tests/integration/test_p4_pipeline.py through a fake `zeek` that just writes those Zeek-format log
lines, then persists the result. The capture itself is a header-only pcap (valid magic, no packets);
nothing here is, or imitates, a real capture, and no number from it is a performance claim.
"""

import json
import uuid
from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.config import PipelineSettings, Settings
from app.db.jobs import enqueue
from app.db.models import Base, Investigation
from app.db.persist import persist_analysis
from app.worker.analysis_config import load_analysis_config
from app.worker.pipeline import analyze_capture
from tests.helpers import capinfos_table, fake_executable
from tests.integration.test_p4_pipeline import storyline_logs

PCAP_HEADER = bytes.fromhex("d4c3b2a1") + b"\x00" * 40  # valid magic, no packets
REPO = Path(__file__).resolve().parents[2]


def make_engine() -> Engine:
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    return engine


def zeek_writing(logs: dict[str, list[dict[str, object]]]) -> str:
    payload = json.dumps(logs)
    return (
        "import json, sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('zeek version 9.0.0'); sys.exit(0)\n"
        f"logs = json.loads({payload!r})\n"
        "for name, rows in logs.items():\n"
        "    with open(name + '.log', 'w') as handle:\n"
        "        handle.write(chr(10).join(json.dumps(r) for r in rows) + chr(10))\n"
    )


def pipeline_settings(
    tmp: Path, logs: dict[str, list[dict[str, object]]] | None = None
) -> PipelineSettings:
    body = zeek_writing(logs if logs is not None else storyline_logs())
    return PipelineSettings(
        config_dir=REPO / "config",
        knowledge_dir=REPO / "knowledge",
        zeek_bin=fake_executable(tmp, "zeek", body),
        capinfos_bin=fake_executable(
            tmp, "capinfos", f"import sys\nprint({capinfos_table(duration='6100')!r}, end='')\n"
        ),
        zeek_expected_version="9.0.0",
    )


def app_settings(tmp: Path, **extra: object) -> Settings:
    uploads, artifacts = tmp / "uploads", tmp / "artifacts"
    uploads.mkdir(exist_ok=True)
    artifacts.mkdir(exist_ok=True)
    base = pipeline_settings(tmp)
    return Settings(
        **base.model_dump(),  # type: ignore[arg-type]
        postgres_db="tw",
        postgres_user="u",
        postgres_password="p",  # type: ignore[arg-type]  # noqa: S106
        uploads_dir=uploads,
        artifacts_dir=artifacts,
        **extra,  # type: ignore[arg-type]
    )


def add_upload(session: Session, settings: Settings, name: str = "storyline.pcap") -> Investigation:
    """A queued investigation whose upload file exists (header-only pcap) and an analyze job."""
    inv_id = str(uuid.uuid4())
    (settings.uploads_dir / f"{inv_id}.pcap").write_bytes(PCAP_HEADER)
    inv = Investigation(
        id=inv_id,
        original_name=name,
        upload_name=f"{inv_id}.pcap",
        sha256="ab" * 32,
        size_bytes=len(PCAP_HEADER),
        status="queued",
        stage="queued",
    )
    session.add(inv)
    session.flush()
    enqueue(session, inv_id, "analyze")
    session.commit()
    return inv


def seed_completed(engine: Engine, settings: Settings) -> str:
    """Analyse the storyline for real (fake zeek) and persist it; returns the investigation id."""
    with Session(engine) as session:
        inv = add_upload(session, settings)
        out_dir = settings.artifacts_dir / inv.id
        status = analyze_capture(settings.uploads_dir / inv.upload_name, out_dir, settings)
        assert status.status == "completed", status
        severity = load_analysis_config(settings).correlation.severity
        persist_analysis(session, inv, out_dir, severity)
        session.commit()
        return inv.id
