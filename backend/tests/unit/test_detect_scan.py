"""DET-SCAN. All inputs are SYNTHETIC evidence tables (tests/detect_helpers.py), never captures."""

from typing import Any

import pytest

from app.detect.base import DetectorOutput
from app.detect.scan import DETECTOR, ScanDetector
from tests.detect_helpers import T0, conn_rows, context, detector_input, frame, tables

SRC, DST = "10.0.0.5", "10.0.0.9"


def run(rows: list[dict[str, Any]], **kw: Any) -> DetectorOutput:
    return DETECTOR.run(detector_input(tables(conn=frame("conn", rows)), **kw))


def vertical(n: int, spacing: float, state: str = "S0") -> list[dict[str, Any]]:
    return conn_rows(
        SRC, DST, [i * spacing for i in range(n)], list(range(1000, 1000 + n)), state=state
    )


def test_identity() -> None:
    assert (DETECTOR.detector_id, DETECTOR.version) == ("DET-SCAN", "1.0.0")
    assert isinstance(DETECTOR, ScanDetector)


# ---- vertical ---------------------------------------------------------------------------
def test_vertical_fires_at_the_threshold_and_records_everything() -> None:
    [f] = run(vertical(50, 1.0)).findings
    assert (f.type, f.primary_entity, f.secondary_entities) == ("SCAN", SRC, [DST])
    assert f.metrics["scan_type"] == "vertical"
    assert f.metrics["distinct_dst_ports"] == 50 and f.metrics["distinct_dst_hosts"] == 1
    assert f.metrics["failed_share"] == 1.0 and f.metrics["connections"] == 50
    assert f.thresholds["vertical_ports"] == 50 and f.thresholds["window_short_s"] == 60
    assert f.confidence == "high" and f.severity_base == 2.0
    assert f.evidence_count == 50 and len(f.evidence_refs) == 50
    assert f.start_ts.timestamp() == pytest.approx(T0) and f.end_ts.timestamp() > T0 + 49
    assert f.benign_causes and f.detector_version == "1.0.0"


def test_vertical_is_silent_one_port_below_the_threshold() -> None:
    assert run(vertical(49, 1.0)).findings == []


def test_vertical_window_is_closed_at_exactly_sixty_seconds() -> None:
    # 50 ports whose first and last probes are exactly 60 s apart are inside one window
    rows = conn_rows(SRC, DST, [i * (60 / 49) for i in range(50)], list(range(1000, 1050)))
    assert [f.metrics["scan_type"] for f in run(rows).findings] == ["vertical"]
    # ...but 61 s apart is not a fast scan (and 50 ports are far below the slow threshold)
    rows = conn_rows(SRC, DST, [i * (61 / 49) for i in range(50)], list(range(1000, 1050)))
    assert run(rows).findings == []


def test_repeated_ports_do_not_count_twice() -> None:
    rows = conn_rows(
        SRC, DST, [float(i) for i in range(200)], [1000 + (i % 49) for i in range(200)]
    )
    assert run(rows).findings == []


def test_slow_vertical_fires_only_when_the_fast_rule_does_not() -> None:
    [f] = run(vertical(100, 5.0)).findings  # 100 ports over 495 s: not 50 within any 60 s
    assert f.metrics["scan_type"] == "slow_vertical" and f.metrics["window_s"] == 600
    assert f.metrics["distinct_dst_ports"] == 100
    assert run(vertical(99, 5.0)).findings == []
    # a fast scan of 120 ports is reported once, as vertical, not also as slow_vertical
    assert [f.metrics["scan_type"] for f in run(vertical(120, 0.5)).findings] == ["vertical"]


# ---- horizontal -------------------------------------------------------------------------
def horizontal(n: int, spacing: float = 1.0, state: str = "S0") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i in range(n):
        rows += conn_rows(SRC, f"10.0.1.{i + 1}", [i * spacing], 445, state=state)
    return rows


def test_horizontal_fires_at_twenty_hosts_not_nineteen() -> None:
    [f] = run(horizontal(20)).findings
    assert f.metrics["scan_type"] == "horizontal"
    assert f.metrics["distinct_dst_hosts"] == 20 and f.metrics["distinct_dst_ports"] == 1
    assert f.secondary_entities == sorted(f.secondary_entities) and len(f.secondary_entities) == 20
    assert run(horizontal(19)).findings == []


def test_horizontal_spread_over_more_than_a_minute_is_silent() -> None:
    assert run(horizontal(20, spacing=4.0)).findings == []  # 76 s end to end


def test_horizontal_secondary_entities_are_capped_but_the_metric_is_not() -> None:
    [f] = run(horizontal(80, spacing=0.5)).findings
    assert len(f.secondary_entities) == 50 and f.metrics["distinct_dst_hosts"] == 80


# ---- confidence -------------------------------------------------------------------------
def test_confidence_is_high_at_a_failed_share_of_point_six_and_medium_below() -> None:
    def mixed(failed: int) -> list[dict[str, Any]]:
        rows = vertical(50, 1.0)
        for i, row in enumerate(rows):
            row["conn_state"] = "REJ" if i < failed else "SF"
        return rows

    [high] = run(mixed(30)).findings  # 30/50 = 0.6
    [medium] = run(mixed(29)).findings  # 0.58
    assert (high.confidence, high.metrics["failed_share"]) == ("high", 0.6)
    assert (medium.confidence, medium.metrics["failed_share"]) == ("medium", 0.58)


@pytest.mark.parametrize("state", ["S0", "REJ", "RSTO", "RSTR", "RSTOS0", "SH", "OTH"])
def test_every_documented_failed_state_counts(state: str) -> None:
    [f] = run(vertical(50, 1.0, state=state)).findings
    assert f.metrics["failed_share"] == 1.0


def test_completed_connections_are_not_failures() -> None:
    [f] = run(vertical(50, 1.0, state="SF")).findings
    assert f.metrics["failed_share"] == 0.0 and f.confidence == "medium"


# ---- suppression, scope, robustness -----------------------------------------------------
def test_known_scanner_is_suppressed_but_counted() -> None:
    out = run(vertical(50, 1.0), network=context(known_hosts={"scanners": [SRC]}))
    assert out.findings == [] and out.suppressed == {"known_scanner": 1}


def test_icmp_and_missing_ports_are_ignored() -> None:
    icmp = conn_rows(SRC, DST, [float(i) for i in range(60)], list(range(60)), proto="icmp")
    assert run(icmp).findings == []
    rows = vertical(60, 1.0)
    for row in rows:
        row["resp_p"] = None
    assert run(rows).findings == []


def test_empty_tables_and_unordered_input() -> None:
    assert DETECTOR.run(detector_input()).findings == []
    rows = vertical(50, 1.0)
    assert [f.model_dump() for f in run(rows).findings] == [
        f.model_dump() for f in run(list(reversed(rows))).findings
    ]


def test_evidence_is_capped_to_the_configured_sample() -> None:
    [f] = run(vertical(300, 0.1)).findings
    assert f.evidence_count == 300 and len(f.evidence_refs) == 200
    assert f.evidence_refs == sorted(f.evidence_refs, key=lambda u: int(u.rsplit("-", 1)[1]))


def test_two_sources_scanning_one_host_give_two_findings() -> None:
    rows = vertical(50, 1.0) + conn_rows(
        "10.0.0.6", DST, [float(i) for i in range(50)], list(range(2000, 2050))
    )
    assert sorted(f.primary_entity for f in run(rows).findings) == [SRC, "10.0.0.6"]


def test_benign_shapes_do_not_fire() -> None:
    """Many connections to one port, or a few hosts and ports, are not scans."""
    web = conn_rows(SRC, DST, [float(i) for i in range(500)], 443, state="SF")
    few = conn_rows(SRC, DST, [float(i) for i in range(30)], list(range(8000, 8030)))
    few_hosts = [r for i in range(15) for r in conn_rows(SRC, f"10.0.2.{i + 1}", [float(i)], 22)]
    assert run(web + few + few_hosts).findings == []
