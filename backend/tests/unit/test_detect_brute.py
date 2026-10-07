"""DET-BRUTE. All inputs are SYNTHETIC evidence tables (tests/detect_helpers.py), never captures."""

from typing import Any

import pytest

from app.detect.base import DetectorOutput
from app.detect.brute import DETECTOR
from tests.detect_helpers import T0, conn_rows, detector_input, frame, tables

SRC, DST = "10.0.0.5", "10.0.0.9"


def ftp_rows(n: int, spacing: float = 1.0, code: int = 530, src: str = SRC, dst: str = DST) -> Any:
    return [
        {
            "ts": T0 + i * spacing,
            "uid": f"F-{src}-{dst}-{i}",
            "orig_h": src,
            "resp_h": dst,
            "reply_code": code,
            "command": "PASS",
        }
        for i in range(n)
    ]


def http_rows(
    n: int, spacing: float = 1.0, status: int = 401, uri: str = "/login", host: str = "a"
) -> Any:
    return [
        {
            "ts": T0 + i * spacing,
            "uid": f"H-{uri.encode().hex()}-{i}",
            "orig_h": SRC,
            "resp_h": DST,
            "status_code": status,
            "uri": uri,
            "host": host,
        }
        for i in range(n)
    ]


def run(**given: Any) -> DetectorOutput:
    return DETECTOR.run(detector_input(tables(**{k: frame(k, v) for k, v in given.items()})))


def login_conns(
    n: int,
    port: int = 22,
    spacing: float = 5.0,
    duration: float = 2.0,
    sizes: Any = 1200,
    src: str = SRC,
    dst: str = DST,
) -> Any:
    return conn_rows(
        src, dst, [i * spacing for i in range(n)], port, duration=duration, orig_bytes=sizes
    )


def test_identity() -> None:
    assert (DETECTOR.detector_id, DETECTOR.version) == ("DET-BRUTE", "1.0.0")


# ---- FTP --------------------------------------------------------------------------------
def test_ftp_fires_at_ten_530_replies_with_high_confidence() -> None:
    [f] = run(ftp=ftp_rows(10)).findings
    assert (f.type, f.primary_entity, f.secondary_entities) == ("BRUTE", SRC, [DST])
    assert f.confidence == "high" and f.severity_base == 3.0
    assert f.metrics["service"] == "ftp" and f.metrics["failures_observed"] == 10
    assert f.metrics["variant"] == "single_target" and f.thresholds["ftp_failures"] == 10
    assert f.evidence_count == 10


def test_ftp_is_silent_below_ten_other_codes_and_outside_the_window() -> None:
    assert run(ftp=ftp_rows(9)).findings == []
    assert run(ftp=ftp_rows(10, code=230)).findings == []
    # 10 failures but spread over more than 5 minutes: never 10 inside one window
    assert run(ftp=ftp_rows(10, spacing=40.0)).findings == []
    # exactly 300 s between first and last still counts (closed window)
    assert len(run(ftp=ftp_rows(10, spacing=300 / 9)).findings) == 1


# ---- HTTP -------------------------------------------------------------------------------
def test_http_fires_at_twenty_failures_to_the_same_uri() -> None:
    [f] = run(http=http_rows(20)).findings
    assert f.confidence == "high" and f.metrics["service"] == "http"
    assert f.metrics["failures_observed"] == 20 and f.thresholds["http_failures"] == 20
    assert "/login" not in str(f.model_dump())  # capture-derived strings are not stored


def test_http_requires_the_same_uri_and_the_401_403_codes() -> None:
    assert run(http=http_rows(19)).findings == []
    mixed = http_rows(10, uri="/a") + http_rows(10, uri="/b")  # 20 failures, two URIs
    assert run(http=mixed).findings == []
    assert run(http=http_rows(20, status=404)).findings == []
    assert len(run(http=http_rows(20, status=403)).findings) == 1


def test_http_reports_one_finding_per_pair_using_the_strongest_uri() -> None:
    both = http_rows(20, uri="/a") + http_rows(30, uri="/b")
    [f] = run(http=both).findings
    assert f.metrics["failures_observed"] == 30


# ---- SSH / RDP / Telnet -----------------------------------------------------------------
def test_ssh_pattern_fires_with_medium_confidence_and_says_inferred() -> None:
    [f] = run(conn=login_conns(10)).findings
    assert f.confidence == "medium" and f.metrics["service"] == "ssh"
    assert f.metrics["failure_kind"] == "inferred_from_connection_pattern"
    assert f.metrics["connections"] == 10 and f.metrics["orig_bytes_cv"] == 0.0


def test_ssh_boundaries() -> None:
    assert run(conn=login_conns(9)).findings == []
    assert run(conn=login_conns(10, duration=30.0)).findings == []  # median must be < 30 s
    assert len(run(conn=login_conns(10, duration=29.9)).findings) == 1
    assert run(conn=login_conns(10, spacing=40.0)).findings == []  # not within 5 minutes


def test_ssh_byte_size_variation_must_stay_below_point_three() -> None:
    steady = [1000, 1100] * 5  # cv ~ 0.048
    varied = [100, 5000] * 5  # cv ~ 0.96
    assert len(run(conn=login_conns(10, sizes=steady)).findings) == 1
    assert run(conn=login_conns(10, sizes=varied)).findings == []


def test_connections_without_a_duration_cannot_be_judged_short() -> None:
    rows = login_conns(10)
    rows[3]["duration"] = None
    assert run(conn=rows).findings == []


@pytest.mark.parametrize(("port", "service"), [(22, "ssh"), (3389, "rdp"), (23, "telnet")])
def test_each_opaque_login_service_is_recognised(port: int, service: str) -> None:
    [f] = run(conn=login_conns(10, port=port)).findings
    assert f.metrics["service"] == service


def test_successful_ssh_logins_reported_by_zeek_are_left_out() -> None:
    rows = login_conns(10)
    ok = [
        {"ts": r["ts"], "uid": r["uid"], "orig_h": SRC, "resp_h": DST, "auth_success": True}
        for r in rows[:3]
    ]
    assert run(conn=rows, ssh=ok).findings == []  # 7 left, below the minimum
    failed = [{**r, "auth_success": False} for r in ok]
    assert len(run(conn=rows, ssh=failed).findings) == 1  # failures are not excluded
    assert len(run(conn=login_conns(10)).findings) == 1


def test_a_busy_web_server_connection_pattern_is_not_a_login_attack() -> None:
    assert run(conn=login_conns(50, port=443)).findings == []


# ---- spraying ---------------------------------------------------------------------------
def test_one_source_failing_against_five_hosts_is_a_spray() -> None:
    rows: list[dict[str, Any]] = []
    for i in range(5):
        rows += ftp_rows(10, dst=f"10.0.1.{i + 1}")
    out = run(ftp=rows)
    assert len(out.findings) == 5
    assert {f.metrics["variant"] for f in out.findings} == {"spray"}
    assert {f.metrics["distinct_targets"] for f in out.findings} == {5}


def test_four_hosts_is_not_yet_a_spray_and_services_are_counted_separately() -> None:
    rows: list[dict[str, Any]] = []
    for i in range(4):
        rows += ftp_rows(10, dst=f"10.0.1.{i + 1}")
    assert {f.metrics["variant"] for f in run(ftp=rows).findings} == {"single_target"}
    # a different service (http) does not add targets to ftp's count
    assert {f.metrics["variant"] for f in run(ftp=rows, http=http_rows(20)).findings} == {
        "single_target"
    }
    assert len(run(ftp=rows, http=http_rows(20)).findings) == 5


# ---- robustness -------------------------------------------------------------------------
def test_empty_tables_and_missing_values_do_not_fail() -> None:
    assert DETECTOR.run(detector_input()).findings == []
    rows = ftp_rows(10)
    rows[0]["resp_h"] = None
    assert run(ftp=rows).findings == []  # 9 usable rows


def test_output_is_deterministic_and_order_independent() -> None:
    rows = ftp_rows(12)
    a = [f.model_dump() for f in run(ftp=rows).findings]
    b = [f.model_dump() for f in run(ftp=list(reversed(rows))).findings]
    assert a == b
