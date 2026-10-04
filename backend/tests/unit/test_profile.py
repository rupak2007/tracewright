from pathlib import Path
from typing import Any

import pytest

from app.core.errors import ConfigError
from app.ingest.capinfos import CapInfo
from app.ingest.normalise import normalise_logs
from app.ingest.validate import CaptureFileInfo, CaptureFormat
from app.profile.context import NetworkContext
from app.profile.profile import CaptureProfile, build_profile
from app.profile.warnings import (
    ProfileConfig,
    WarningInputs,
    compute_warnings,
    load_profile_config,
    max_beacon_interval_s,
)
from tests.helpers import conn_row, write_zeek_logs

CFG = ProfileConfig(
    beacon_min_events=10,
    beacon_target_interval_s=300,
    one_sided_no_handshake_share=0.5,
    one_sided_min_tcp_connections=20,
    weird_share_of_connections=0.05,
    weird_min_count=10,
    snaplen_min_bytes=1518,
    small_host_population_min_internal=5,
    weak_exfil_baseline_min_pairs=20,
    normalise_skipped_share=0.01,
    top_talkers=3,
)
CTX = NetworkContext.model_validate({"internal_cidrs": ["10.0.0.0/8"]})
FILE_INFO = CaptureFileInfo(CaptureFormat.PCAP, 1234, "ab" * 32)


def healthy(**overrides: Any) -> WarningInputs:
    base: dict[str, Any] = {
        "connections": 1000,
        "tcp_connections": 800,
        "tcp_no_handshake": 10,
        "weird_rows": 1,
        "dns_queries": 50,
        "internal_hosts": 30,
        "internal_external_pairs": 40,
        "span_s": 7200.0,
        "snaplen": 262144,
        "normalise_lines_total": 5000,
        "normalise_lines_skipped": 0,
    }
    base.update(overrides)
    return WarningInputs(**base)


def codes(inputs: WarningInputs) -> set[str]:
    return {w.code for w in compute_warnings(inputs, CFG)}


def test_healthy_capture_has_no_warnings() -> None:
    assert compute_warnings(healthy(), CFG) == []


def test_nothing_to_analyse_is_the_only_warning_when_no_connections() -> None:
    assert codes(healthy(connections=0, dns_queries=0)) == {"NOTHING_TO_ANALYSE"}


def test_short_capture_reports_max_detectable_interval() -> None:
    [warning] = compute_warnings(healthy(span_s=600.0), CFG)
    assert warning.code == "CAPTURE_SHORT_FOR_BEACONS"
    assert warning.metric["max_detectable_interval_s"] == pytest.approx(60.0)
    assert "60 s" in warning.message


def test_beacon_boundary() -> None:
    assert "CAPTURE_SHORT_FOR_BEACONS" in codes(healthy(span_s=2999.0))
    assert "CAPTURE_SHORT_FOR_BEACONS" not in codes(healthy(span_s=3000.0))
    assert "CAPTURE_SHORT_FOR_BEACONS" in codes(healthy(span_s=None))


def test_max_beacon_interval() -> None:
    assert max_beacon_interval_s(3600.0, CFG) == pytest.approx(360.0)
    assert max_beacon_interval_s(0.0, CFG) is None and max_beacon_interval_s(None, CFG) is None


def test_one_sided_needs_enough_connections_and_share() -> None:
    assert "ONE_SIDED_TRAFFIC" in codes(healthy(tcp_connections=100, tcp_no_handshake=50))
    assert "ONE_SIDED_TRAFFIC" not in codes(healthy(tcp_connections=100, tcp_no_handshake=49))
    assert "ONE_SIDED_TRAFFIC" not in codes(healthy(tcp_connections=19, tcp_no_handshake=19))


def test_truncated_packets() -> None:
    assert "TRUNCATED_PACKETS" in codes(healthy(snaplen=96))
    assert "TRUNCATED_PACKETS" not in codes(healthy(snaplen=1518))
    assert "TRUNCATED_PACKETS" not in codes(healthy(snaplen=None))


def test_high_weird_count() -> None:
    assert "HIGH_WEIRD_COUNT" in codes(healthy(weird_rows=60))
    assert "HIGH_WEIRD_COUNT" not in codes(healthy(weird_rows=49))
    assert "HIGH_WEIRD_COUNT" not in codes(healthy(connections=10, weird_rows=9))  # below min count


def test_small_host_population_no_dns_weak_exfil() -> None:
    result = codes(healthy(internal_hosts=2, dns_queries=0, internal_external_pairs=3))
    assert result == {"SMALL_HOST_POPULATION", "NO_DNS", "WEAK_BASELINE_EXFIL"}
    assert "WEAK_BASELINE_EXFIL" not in codes(healthy(internal_external_pairs=20))


def test_normalise_skipped_high() -> None:
    assert "NORMALISE_SKIPPED_HIGH" in codes(healthy(normalise_lines_skipped=51))
    assert "NORMALISE_SKIPPED_HIGH" not in codes(healthy(normalise_lines_skipped=50))


def test_shipped_profile_yaml_loads(config_dir: Path) -> None:
    assert load_profile_config(config_dir / "profile.yaml").beacon_min_events == 10


def test_profile_config_rejects_bad_input(tmp_path: Path) -> None:
    path = tmp_path / "profile.yaml"
    path.write_text("beacon_min_events: 0\n")
    with pytest.raises(ConfigError):
        load_profile_config(path)


def _profile(tmp_path: Path, logs: dict[str, list[Any]], cap: CapInfo) -> CaptureProfile:
    write_zeek_logs(tmp_path / "zeek", logs)
    tables, stats = normalise_logs(tmp_path / "zeek", tmp_path / "tables")
    return build_profile(FILE_INFO, cap, "9.0.0", tables, stats, CTX, CFG)


def test_build_profile_from_tables(tmp_path: Path) -> None:
    logs = {
        "conn": [
            conn_row(1.0, "10.0.0.1", "10.0.0.2", 22, service="ssh", orig_ip_bytes=1000),
            conn_row(2.0, "10.0.0.1", "8.8.8.8", 53, proto="udp", service="dns", history="Dd"),
            conn_row(3.0, "10.0.0.3", "8.8.8.8", 443, service=None, history="D"),
            conn_row(4.0, "10.0.0.3", "1.1.1.1", 443),
        ],
        "dns": [{"ts": 2.0, "uid": "d1", "query": "a.example"}],
        "weird": [{"ts": 1.5, "name": "bad_HTTP_request"}, {"ts": 2.5, "name": "bad_HTTP_request"}],
    }
    cap = CapInfo(40, 1.0, 4.0, 3.0, 65535, "ether")
    p = _profile(tmp_path, logs, cap)
    assert p.connections == 4 and p.dns_queries == 1
    assert (p.internal_hosts, p.external_hosts) == (3, 2)
    assert p.internal_external_pairs == 3  # (.1,8.8.8.8) (.3,8.8.8.8) (.3,1.1.1.1)
    assert p.services == {"dns": 1, "http": 1, "ssh": 1, "unknown": 1}
    assert p.weird_by_name == {"bad_HTTP_request": 2}
    assert p.tcp_connections == 3 and p.tcp_no_handshake == 1  # history "D" has no S/h
    assert p.total_ip_bytes == 1400 + 3 * 700
    assert p.max_beacon_interval_s == pytest.approx(0.3)
    assert p.top_talkers[0].host in {"8.8.8.8", "10.0.0.1", "10.0.0.3"}
    assert [t.bytes for t in p.top_talkers] == sorted(
        (t.bytes for t in p.top_talkers), reverse=True
    )
    assert p.table_rows["conn"] == 4 and p.file.sha256 == "ab" * 32
    assert "CAPTURE_SHORT_FOR_BEACONS" in {w.code for w in p.warnings}


def test_build_profile_for_empty_capture(tmp_path: Path) -> None:
    p = _profile(tmp_path, {}, CapInfo(0, None, None, None, 65535, "ether"))
    assert p.connections == 0 and p.top_talkers == [] and p.total_ip_bytes == 0
    assert [w.code for w in p.warnings] == ["NOTHING_TO_ANALYSE"]


def test_profile_is_deterministic(tmp_path: Path) -> None:
    logs = {"conn": [conn_row(float(i), f"10.0.0.{i % 4}", "8.8.8.8", 443) for i in range(1, 30)]}
    cap = CapInfo(100, 1.0, 30.0, 29.0, 65535, "ether")
    a = _profile(tmp_path / "a", logs, cap).model_dump_json()
    b = _profile(tmp_path / "b", logs, cap).model_dump_json()
    assert a == b
