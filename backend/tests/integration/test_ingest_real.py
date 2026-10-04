"""End-to-end ingest against the REAL Zeek and capinfos binaries (no fakes).

Skipped unless `zeek` is on PATH, i.e. they run inside the worker image (/tmp must allow exec
because the unit tests run fake tool scripts; the real worker keeps the default noexec tmpfs):
    docker build --target test -t tracewright-worker-test -f backend/Dockerfile.worker backend
    docker run --rm --network none --read-only --tmpfs /tmp:rw,exec --cap-drop ALL \
        --security-opt no-new-privileges:true -v ./config:/config:ro tracewright-worker-test
Expected values come from the fixture construction in tests/fixtures/make_fixtures.py.
"""

import hashlib
import json
import shutil
from pathlib import Path

import pandas as pd
import pytest

from app.core.config import PipelineSettings
from app.ingest.normalise import read_tables
from app.worker.pipeline import AnalysisStatus, analyze_capture, read_profile

pytestmark = [
    pytest.mark.requires_zeek,
    pytest.mark.skipif(shutil.which("zeek") is None, reason="real Zeek not installed"),
]


@pytest.fixture
def settings(config_dir: Path) -> PipelineSettings:
    return PipelineSettings(config_dir=config_dir)


def _analyze(captures: Path, name: str, out: Path, settings: PipelineSettings) -> AnalysisStatus:
    return analyze_capture(captures / name, out, settings)


def test_basic_pcap_full_pipeline(
    fixture_captures: Path, tmp_path: Path, settings: PipelineSettings
) -> None:
    out = tmp_path / "out"
    status = _analyze(fixture_captures, "basic.pcap", out, settings)
    assert status.status == "completed", status.error_message
    assert status.zeek_version is not None and status.zeek_version.startswith("9.")

    # SHA-256 recorded and equal to an independent hash of the original, which is untouched.
    source = (fixture_captures / "basic.pcap").read_bytes()
    assert status.sha256 == hashlib.sha256(source).hexdigest()

    # Raw Zeek JSON logs exist and are JSON lines.
    for name in ("conn", "dns", "http", "ssl"):
        first = (out / "zeek" / f"{name}.log").read_text().splitlines()[0]
        assert isinstance(json.loads(first), dict)

    tables = read_tables(out / "tables")
    states = tables.conn["conn_state"].value_counts().to_dict()
    assert states == {"SF": 4, "REJ": 1, "S0": 1, "OTH": 1}
    assert len(tables.conn) == 7
    assert len(tables.dns) == 2
    assert set(tables.dns["rcode_name"]) == {"NOERROR", "NXDOMAIN"}
    nx = tables.dns[tables.dns["rcode_name"] == "NXDOMAIN"].iloc[0]
    assert nx["query"] == "nope.example.com" and pd.isna(nx["answers"])
    ok = tables.dns[tables.dns["rcode_name"] == "NOERROR"].iloc[0]
    assert list(ok["answers"]) == ["93.184.216.34"]
    http = tables.http.iloc[0]
    assert (http["method"], http["host"], http["uri"], http["status_code"]) == (
        "GET",
        "intranet.example",
        "/index.html",
        200,
    )
    rejected = tables.conn[tables.conn["conn_state"] == "REJ"].iloc[0]
    assert (rejected["resp_h"], rejected["resp_p"]) == ("10.0.0.10", 81)
    assert len(tables.ssh) == len(tables.ftp) == len(tables.weird) == 0

    profile = read_profile(out)
    assert profile.capture.packets == 29 and profile.capture.link_type == "ether"
    assert profile.capture.snaplen == 65535
    assert profile.connections == 7 and profile.dns_queries == 2
    assert (profile.internal_hosts, profile.external_hosts) == (3, 1)
    assert profile.internal_external_pairs == 1
    assert profile.tcp_connections == 4 and profile.tcp_no_handshake == 0
    assert profile.services == {"unknown": 4, "dns": 2, "http": 1}
    assert profile.top_talkers[0].host == "10.0.0.5"
    assert {w.code for w in profile.warnings} == {
        "CAPTURE_SHORT_FOR_BEACONS",
        "SMALL_HOST_POPULATION",
        "WEAK_BASELINE_EXFIL",
    }
    assert json.loads((out / "status.json").read_text())["status"] == "completed"


def test_pcapng_is_accepted(
    fixture_captures: Path, tmp_path: Path, settings: PipelineSettings
) -> None:
    out = tmp_path / "out"
    status = _analyze(fixture_captures, "basic.pcapng", out, settings)
    assert status.status == "completed", status.error_message
    profile = read_profile(out)
    assert profile.file.format == "pcapng" and profile.connections == 7
    assert profile.capture.snaplen is None  # pcapng records no global snaplen here


def test_truncated_capture_fails_cleanly_at_zeek(
    fixture_captures: Path, tmp_path: Path, settings: PipelineSettings
) -> None:
    out = tmp_path / "out"
    status = _analyze(fixture_captures, "truncated.pcap", out, settings)
    assert (status.status, status.stage, status.error_code) == (
        "failed",
        "zeek_parse",
        "ZEEK_FAILED",
    )
    assert "truncated" in (status.error_message or "")
    assert "truncated" in (out / "logs" / "zeek.stderr.txt").read_text()
    assert not (out / "profile.json").exists()
    assert json.loads((out / "status.json").read_text())["status"] == "failed"


@pytest.mark.parametrize(
    ("name", "code"),
    [("not_a_pcap.bin", "FILE_TYPE_INVALID"), ("basic.pcap.gz", "FILE_COMPRESSED")],
)
def test_invalid_files_rejected_before_zeek(
    fixture_captures: Path, tmp_path: Path, settings: PipelineSettings, name: str, code: str
) -> None:
    out = tmp_path / "out"
    status = _analyze(fixture_captures, name, out, settings)
    assert (status.status, status.stage, status.error_code) == ("failed", "validate", code)
    assert list((out / "zeek").iterdir()) == []  # Zeek never ran


def test_empty_capture_completes_with_nothing_to_analyse(
    fixture_captures: Path, tmp_path: Path, settings: PipelineSettings
) -> None:
    out = tmp_path / "out"
    status = _analyze(fixture_captures, "empty.pcap", out, settings)
    assert status.status == "completed", status.error_message
    profile = read_profile(out)
    assert profile.connections == 0 and profile.capture.packets == 0
    assert [w.code for w in profile.warnings] == ["NOTHING_TO_ANALYSE"]
    assert all(len(getattr(read_tables(out / "tables"), n)) == 0 for n in ("conn", "dns", "http"))


def test_identical_input_gives_identical_output(
    fixture_captures: Path, tmp_path: Path, settings: PipelineSettings
) -> None:
    runs = []
    for name in ("a", "b"):
        out = tmp_path / name
        assert _analyze(fixture_captures, "basic.pcap", out, settings).status == "completed"
        runs.append(out)
    assert (runs[0] / "profile.json").read_text() == (runs[1] / "profile.json").read_text()
    a, b = read_tables(runs[0] / "tables"), read_tables(runs[1] / "tables")
    for name in ("conn", "dns", "http", "ssl"):
        pd.testing.assert_frame_equal(getattr(a, name), getattr(b, name))
