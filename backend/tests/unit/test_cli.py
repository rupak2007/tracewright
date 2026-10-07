import json
from pathlib import Path

import pytest

from app.cli import EXIT_ANALYSIS_FAILED, EXIT_OK, EXIT_USAGE, main
from tests.helpers import capinfos_table, conn_row, fake_executable

PCAP = bytes.fromhex("d4c3b2a1") + b"\x00" * 40
ZEEK = f"""import json, sys
if sys.argv[1:] == ["--version"]:
    print("zeek version 9.0.0"); sys.exit(0)
open("conn.log", "w").write(json.dumps({json.dumps(conn_row(1.0))}) + "\\n")
"""


@pytest.fixture
def tools(tmp_path: Path, config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("ZEEK_BIN", fake_executable(tmp_path, "zeek", ZEEK))
    monkeypatch.setenv(
        "CAPINFOS_BIN",
        fake_executable(tmp_path, "capinfos", f"print({capinfos_table()!r}, end='')\n"),
    )
    monkeypatch.setenv("ZEEK_EXPECTED_VERSION", "9.0.0")
    pcap = tmp_path / "in.pcap"
    pcap.write_bytes(PCAP)
    return pcap


def test_analyze_ok(tools: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "out"
    assert main(["analyze", str(tools), "--out", str(out)]) == EXIT_OK
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "completed" and summary["connections"] == 1
    assert "NO_DNS" in summary["warnings"] and summary["findings"] == 0
    assert (out / "profile.json").exists() and (out / "tables" / "conn.parquet").exists()


def test_analysis_failure_exit_code(
    tools: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tools.write_bytes(b"garbage")
    assert main(["analyze", str(tools), "--out", str(tmp_path / "out")]) == EXIT_ANALYSIS_FAILED
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "failed" and summary["error"]["code"] == "FILE_TYPE_INVALID"


def test_usage_error_exit_code(
    tools: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "x").write_text("x")
    assert main(["analyze", str(tools), "--out", str(out)]) == EXIT_USAGE
    assert json.loads(capsys.readouterr().out)["code"] == "OUTPUT_DIR_NOT_EMPTY"


def test_config_dir_flag(tools: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        ["analyze", str(tools), "--out", str(tmp_path / "o"), "--config-dir", str(tmp_path)]
    )
    assert code == EXIT_USAGE and json.loads(capsys.readouterr().out)["code"] == "CONFIG_INVALID"
