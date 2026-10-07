"""Stage orchestration and lifecycle, with fake zeek/capinfos executables.

These verify control flow only. Real Zeek/capinfos behaviour is covered by the
`requires_zeek` integration tests, which run in the worker image.
"""

import json
from pathlib import Path

import pytest

from app.core.config import PipelineSettings
from app.core.errors import ConfigError, IngestError
from app.ingest.normalise import read_tables
from app.worker.pipeline import analyze_capture, read_profile
from tests.helpers import capinfos_table, conn_row, fake_executable

PCAP = bytes.fromhex("d4c3b2a1") + b"\x00" * 40

_ROWS = json.dumps([conn_row(1.0), conn_row(2.0, resp="8.8.8.8", resp_p=443)])
ZEEK_OK = (
    "import json, sys\n"
    "if sys.argv[1:] == ['--version']:\n"
    "    print('zeek version 9.0.0'); sys.exit(0)\n"
    f"rows = json.loads({_ROWS!r})\n"
    "lines = [json.dumps(r) for r in rows] + ['{broken']\n"
    "open('conn.log', 'w').write(chr(10).join(lines) + chr(10))\n"
)
ZEEK_FAIL = """import sys
if sys.argv[1:] == ["--version"]:
    print("zeek version 9.0.0"); sys.exit(0)
sys.stderr.write("fatal error: truncated dump file\\n"); sys.exit(1)
"""
CAPINFOS_OK = f"import sys\nprint({capinfos_table()!r}, end='')\n"


def _settings(tmp_path: Path, config_dir: Path, zeek_body: str, **kw: object) -> PipelineSettings:
    return PipelineSettings(
        config_dir=config_dir,
        zeek_bin=fake_executable(tmp_path, "zeek", zeek_body),
        capinfos_bin=fake_executable(tmp_path, "capinfos", CAPINFOS_OK),
        zeek_expected_version="9.0.0",
        **kw,  # type: ignore[arg-type]
    )


def _pcap(tmp_path: Path, data: bytes = PCAP) -> Path:
    path = tmp_path / "in.pcap"
    path.write_bytes(data)
    return path


def _status(out: Path) -> dict[str, object]:
    return json.loads((out / "status.json").read_text())


def test_happy_path_produces_all_artifacts(tmp_path: Path, config_dir: Path) -> None:
    out = tmp_path / "out"
    status = analyze_capture(_pcap(tmp_path), out, _settings(tmp_path, config_dir, ZEEK_OK))
    assert status.status == "completed" and status.error_code is None
    assert status.zeek_version == "9.0.0" and status.sha256 is not None
    assert set(status.stage_ms) == {"validate", "zeek_parse", "normalise", "profile", "detect"}
    assert _status(out)["status"] == "completed"
    profile = read_profile(out)
    assert profile.connections == 2 and profile.zeek_version == "9.0.0"
    assert profile.normalise_lines_skipped == 1  # the {broken line
    assert len(read_tables(out / "tables").conn) == 2
    assert (out / "logs" / "zeek.stderr.txt").exists()
    findings = json.loads((out / "findings.json").read_text())
    assert findings["findings"] == []  # two benign connections: nothing fires
    assert findings["investigation_id"] == f"inv-{status.sha256[:12]}"  # type: ignore[index]
    assert set(findings["detector_versions"]) == {
        "DET-SCAN",
        "DET-BRUTE",
        "DET-DNSTUN",
        "DET-BEACON",
        "DET-EXFIL",
    }
    assert len(findings["config_hash"]) == 64
    assert set(profile.suppressed_findings) == set(findings["detector_versions"])


def test_missing_detector_config_is_a_config_error_before_any_work(
    tmp_path: Path, config_dir: Path
) -> None:
    broken = tmp_path / "cfg"
    broken.mkdir()
    for name in ("network.yaml", "profile.yaml"):
        (broken / name).write_bytes((config_dir / name).read_bytes())
    out = tmp_path / "out"
    with pytest.raises(ConfigError):
        analyze_capture(_pcap(tmp_path), out, _settings(tmp_path, broken, ZEEK_OK))
    assert not out.exists()


def test_findings_are_deterministic_across_runs(tmp_path: Path, config_dir: Path) -> None:
    results = []
    for name in ("a", "b"):
        out = tmp_path / name
        analyze_capture(_pcap(tmp_path), out, _settings(tmp_path, config_dir, ZEEK_OK))
        results.append((out / "findings.json").read_bytes())
    assert results[0] == results[1]


def test_invalid_capture_fails_at_validate_and_never_runs_zeek(
    tmp_path: Path, config_dir: Path
) -> None:
    marker = tmp_path / "zeek_ran"
    body = f"open({str(marker)!r}, 'w').write('x')\n"
    out = tmp_path / "out"
    status = analyze_capture(
        _pcap(tmp_path, b"MZ not a capture"), out, _settings(tmp_path, config_dir, body)
    )
    assert (status.status, status.stage) == ("failed", "validate")
    assert status.error_code == "FILE_TYPE_INVALID"
    assert not marker.exists()
    assert not (out / "profile.json").exists()
    assert _status(out)["error_code"] == "FILE_TYPE_INVALID"


def test_zeek_failure_is_reported_at_zeek_parse(tmp_path: Path, config_dir: Path) -> None:
    out = tmp_path / "out"
    status = analyze_capture(_pcap(tmp_path), out, _settings(tmp_path, config_dir, ZEEK_FAIL))
    assert (status.status, status.stage) == ("failed", "zeek_parse")
    assert status.error_code == "ZEEK_FAILED"
    assert "truncated dump file" in (status.error_message or "")
    assert "truncated dump file" in (out / "logs" / "zeek.stderr.txt").read_text()
    assert not (out / "profile.json").exists()


def test_zeek_version_mismatch_fails_closed(tmp_path: Path, config_dir: Path) -> None:
    settings = _settings(tmp_path, config_dir, ZEEK_OK).model_copy(
        update={"zeek_expected_version": "8.0.0"}
    )
    status = analyze_capture(_pcap(tmp_path), tmp_path / "out", settings)
    assert (status.status, status.error_code) == ("failed", "ZEEK_UNAVAILABLE")


def test_zeek_timeout(tmp_path: Path, config_dir: Path) -> None:
    body = (
        "import sys, time\n"
        "if sys.argv[1:] == ['--version']:\n    print('zeek version 9.0.0'); sys.exit(0)\n"
        "time.sleep(10)\n"
    )
    settings = _settings(tmp_path, config_dir, body, zeek_timeout_s=1)
    status = analyze_capture(_pcap(tmp_path), tmp_path / "out", settings)
    assert (status.status, status.error_code) == ("failed", "ZEEK_TIMEOUT")


def test_oversize_capture_rejected(tmp_path: Path, config_dir: Path) -> None:
    settings = _settings(tmp_path, config_dir, ZEEK_OK, max_upload_bytes=10)
    status = analyze_capture(_pcap(tmp_path), tmp_path / "out", settings)
    assert status.error_code == "FILE_TOO_LARGE"


def test_unexpected_exception_marks_run_failed(
    tmp_path: Path, config_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr("app.worker.pipeline.normalise_logs", boom)
    out = tmp_path / "out"
    status = analyze_capture(_pcap(tmp_path), out, _settings(tmp_path, config_dir, ZEEK_OK))
    assert (status.status, status.stage) == ("failed", "normalise")
    assert status.error_code == "INTERNAL_ERROR"
    assert "secret internal detail" not in (status.error_message or "")
    assert _status(out)["status"] == "failed"


def test_non_empty_output_dir_refused_and_untouched(tmp_path: Path, config_dir: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    keep = out / "precious.txt"
    keep.write_text("keep me")
    with pytest.raises(IngestError) as exc:
        analyze_capture(_pcap(tmp_path), out, _settings(tmp_path, config_dir, ZEEK_OK))
    assert exc.value.code == "OUTPUT_DIR_NOT_EMPTY"
    assert keep.read_text() == "keep me" and not (out / "status.json").exists()


def test_bad_config_raises_before_any_work(tmp_path: Path) -> None:
    settings = PipelineSettings(config_dir=tmp_path / "missing-config")
    with pytest.raises(ConfigError):
        analyze_capture(_pcap(tmp_path), tmp_path / "out", settings)
    assert not (tmp_path / "out").exists()


def test_original_capture_is_not_modified(tmp_path: Path, config_dir: Path) -> None:
    pcap = _pcap(tmp_path)
    before = pcap.read_bytes()
    analyze_capture(pcap, tmp_path / "out", _settings(tmp_path, config_dir, ZEEK_OK))
    assert pcap.read_bytes() == before
