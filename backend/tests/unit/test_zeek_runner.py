import json
from pathlib import Path

import pytest

from app.core.errors import IngestError
from app.ingest.zeek import run_zeek
from tests.helpers import fake_executable

SITE = Path("site.zeek")


def _run(tmp_path: Path, zeek: str, timeout_s: int = 30):  # type: ignore[no-untyped-def]
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"x")
    return run_zeek(pcap, tmp_path / "zeek", tmp_path / "logs", SITE, zeek, timeout_s)


def test_invocation_is_a_list_with_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "super-secret")
    body = (
        "import json, os, sys\n"
        "open('argv.json', 'w').write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(),\n"
        "    'env': sorted(os.environ)}))\n"
        "open('conn.log', 'w').write('{}\\n')\n"
    )
    result = _run(tmp_path, fake_executable(tmp_path, "zeek", body))
    seen = json.loads((tmp_path / "zeek" / "argv.json").read_text())
    assert seen["argv"][:3] == ["-C", "-D", "-r"]
    assert seen["argv"][3] == str((tmp_path / "cap.pcap").resolve())
    assert seen["argv"][-1] == "LogAscii::use_json=T"
    assert Path(seen["cwd"]).resolve() == (tmp_path / "zeek").resolve()
    assert not any("POSTGRES" in key or "PASSWORD" in key for key in seen["env"])
    assert "conn.log" in result.log_files


def test_nonzero_exit_reports_sanitised_stderr_tail(tmp_path: Path) -> None:
    body = (
        "import sys\n"
        "sys.stderr.write('fatal error: truncated dump file\\x1b[31m\\x00 evil\\n')\n"
        "sys.exit(1)\n"
    )
    with pytest.raises(IngestError) as exc:
        _run(tmp_path, fake_executable(tmp_path, "zeek", body))
    assert exc.value.code == "ZEEK_FAILED"
    assert "truncated dump file" in exc.value.message and "status 1" in exc.value.message
    assert "\x1b" not in exc.value.message and "\x00" not in exc.value.message
    assert "truncated dump file" in (tmp_path / "logs" / "zeek.stderr.txt").read_text(
        errors="replace"
    )


def test_timeout_kills_zeek(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as exc:
        _run(tmp_path, fake_executable(tmp_path, "zeek", "import time\ntime.sleep(10)\n"), 1)
    assert exc.value.code == "ZEEK_TIMEOUT"


def test_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as exc:
        _run(tmp_path, str(tmp_path / "no-such-zeek"))
    assert exc.value.code == "ZEEK_NOT_FOUND"


def test_hostile_filename_is_one_argument(tmp_path: Path) -> None:
    hostile = tmp_path / "a; rm -rf ~ $(touch pwned) `id`.pcap"
    hostile.write_bytes(b"x")
    body = "import json, sys\nopen('argv.json', 'w').write(json.dumps(sys.argv[1:]))\n"
    zeek = fake_executable(tmp_path, "zeek", body)
    run_zeek(hostile, tmp_path / "zeek", tmp_path / "logs", SITE, zeek, 30)
    argv = json.loads((tmp_path / "zeek" / "argv.json").read_text())
    assert argv[3] == str(hostile.resolve())
    assert not (tmp_path / "pwned").exists() and not (tmp_path / "zeek" / "pwned").exists()
