import stat
import sys
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.errors import StartupCheckError
from app.worker.startup import check_data_dirs, check_zeek, zeek_version


def _fake_zeek(tmp_path: Path, body: str) -> str:
    """Create an executable that stands in for zeek (a python script run via the interpreter)."""
    script = tmp_path / "fake_zeek.py"
    script.write_text(body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    wrapper = tmp_path / ("fake_zeek.cmd" if sys.platform == "win32" else "fake_zeek")
    if sys.platform == "win32":
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n')
    else:
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        wrapper.chmod(0o755)
    return str(wrapper)


def _settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    monkeypatch.setenv("POSTGRES_DB", "tw")
    monkeypatch.setenv("POSTGRES_USER", "u")
    monkeypatch.setenv("POSTGRES_PASSWORD", "p")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_zeek_version_parsed(tmp_path: Path) -> None:
    zeek = _fake_zeek(tmp_path, "print('zeek version 9.0.0')\n")
    assert zeek_version(zeek) == "9.0.0"


def test_zeek_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(StartupCheckError, match="cannot run"):
        zeek_version(str(tmp_path / "nope"))


def test_zeek_bad_output(tmp_path: Path) -> None:
    zeek = _fake_zeek(tmp_path, "print('something else')\n")
    with pytest.raises(StartupCheckError, match="unrecognised"):
        zeek_version(zeek)


def test_zeek_nonzero_exit(tmp_path: Path) -> None:
    zeek = _fake_zeek(tmp_path, "import sys; sys.exit(3)\n")
    with pytest.raises(StartupCheckError, match="exited 3"):
        zeek_version(zeek)


def test_pinned_version_mismatch_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    zeek = _fake_zeek(tmp_path, "print('zeek version 9.0.1')\n")
    settings = _settings(monkeypatch, ZEEK_BIN=zeek, ZEEK_EXPECTED_VERSION="9.0.0")
    with pytest.raises(StartupCheckError, match="does not match pinned"):
        check_zeek(settings)


def test_pinned_version_match_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    zeek = _fake_zeek(tmp_path, "print('zeek version 9.0.0')\n")
    settings = _settings(monkeypatch, ZEEK_BIN=zeek, ZEEK_EXPECTED_VERSION="9.0.0")
    assert check_zeek(settings) == "9.0.0"


def test_data_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    uploads, artifacts = tmp_path / "u", tmp_path / "a"
    settings = _settings(monkeypatch, UPLOADS_DIR=str(uploads), ARTIFACTS_DIR=str(artifacts))
    with pytest.raises(StartupCheckError, match="uploads"):
        check_data_dirs(settings)
    uploads.mkdir()
    with pytest.raises(StartupCheckError, match="artifacts"):
        check_data_dirs(settings)
    artifacts.mkdir()
    check_data_dirs(settings)
