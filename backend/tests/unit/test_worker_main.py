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
