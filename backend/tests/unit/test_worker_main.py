from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError

from app.core.errors import StartupCheckError
from app.worker import main as worker_main


class _ImmediateEvent:
    """Stands in for threading.Event so the idle loop returns at once."""

    def set(self) -> None: ...

    def wait(self) -> bool:
        return True


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POSTGRES_DB", "tw")
    monkeypatch.setenv("POSTGRES_USER", "u")
    monkeypatch.setenv("POSTGRES_PASSWORD", "p")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(worker_main, "check_attack_mapping", lambda _s: "19.2")
    monkeypatch.setattr(worker_main, "run_loop", lambda *_: None)
    monkeypatch.setattr(worker_main.signal, "signal", lambda *_: None)
    monkeypatch.setattr(worker_main.threading, "Event", _ImmediateEvent)
    monkeypatch.setattr(worker_main, "configure_logging", lambda *_: None)


def test_main_returns_zero_when_checks_pass(env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_main, "check_zeek", lambda _s: "9.0.0")
    monkeypatch.setattr(worker_main, "check_connection", lambda _e: None)
    assert worker_main.main() == 0


def test_main_fails_when_zeek_check_fails(env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_s: object) -> str:
        raise StartupCheckError("no zeek")

    monkeypatch.setattr(worker_main, "check_zeek", boom)
    assert worker_main.main() == 1


def test_main_fails_when_db_unreachable(env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_e: object) -> None:
        raise OperationalError("SELECT 1", None, Exception("refused"))

    monkeypatch.setattr(worker_main, "check_zeek", lambda _s: "9.0.0")
    monkeypatch.setattr(worker_main, "check_connection", boom)
    assert worker_main.main() == 1


def test_main_fails_when_the_attack_mapping_is_invalid(
    env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_s: object) -> str:
        raise StartupCheckError("T1046 is revoked")

    monkeypatch.setattr(worker_main, "check_zeek", lambda _s: "9.0.0")
    monkeypatch.setattr(worker_main, "check_attack_mapping", boom)
    monkeypatch.setattr(worker_main, "check_connection", lambda _e: None)
    assert worker_main.main() == 1


def test_run_loop_leases_jobs_beats_and_stops_on_request(tmp_path: Path) -> None:
    import threading

    from sqlalchemy.orm import Session

    from app.db import jobs
    from app.db.models import Job, WorkerHeartbeat
    from tests.db_helpers import add_upload, app_settings, make_engine

    settings = app_settings(tmp_path)
    engine = make_engine()
    with Session(engine) as s:
        inv_id = add_upload(s, settings).id
    stop = threading.Event()
    seen: list[int] = []

    def fake_process(session: Session, _settings: object, job: Job, _severity: object) -> None:
        seen.append(job.id)
        jobs.mark_done(session, job)
        session.commit()
        stop.set()

    import app.worker.main as module

    original = module.process
    module.process = fake_process  # type: ignore[assignment]
    try:
        module.run_loop(engine, settings, stop)
    finally:
        module.process = original
    with Session(engine) as s:
        job = s.query(Job).filter_by(investigation_id=inv_id).one()
        assert seen == [job.id] and job.status == "done" and job.worker_id
        assert s.query(WorkerHeartbeat).count() == 1
