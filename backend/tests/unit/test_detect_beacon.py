"""DET-BEACON. All inputs are SYNTHETIC evidence tables (tests/detect_helpers.py)."""

import random
from typing import Any

import numpy as np
import pytest

from app.detect.base import DetectorOutput
from app.detect.beacon import DETECTOR, beacon_scores
from app.detect.config import load_detectors_config
from tests.detect_helpers import (
    SHIPPED_CONFIG,
    T0,
    conn_rows,
    context,
    detector_input,
    frame,
    tables,
)

SRC, DST = "10.0.0.5", "203.0.113.9"
CFG = load_detectors_config(SHIPPED_CONFIG).beacon


def series(n: int, interval: float = 60.0, jitter: float = 0.0, seed: int = 1) -> list[float]:
    rng = random.Random(seed)  # noqa: S311  # seeded, reproducible fixture
    t, out = 0.0, []
    for _ in range(n):
        out.append(t)
        t += interval * (1 + rng.uniform(-jitter, jitter))
    return out


def run(
    conn: list[dict[str, Any]] | None = None, span: float | None = 3600.0, **given: Any
) -> DetectorOutput:
    parts = {"conn": frame("conn", conn or [])}
    parts.update({k: frame(k, v) for k, v in given.items() if k != "network"})
    network = given.get("network")
    return DETECTOR.run(detector_input(tables(**parts), network=network, span_s=span))


def beacon_conns(
    n: int, interval: float = 60.0, jitter: float = 0.0, port: int = 443, **kw: Any
) -> list[dict[str, Any]]:
    return conn_rows(SRC, DST, series(n, interval, jitter), port, **kw)


def test_identity() -> None:
    assert (DETECTOR.detector_id, DETECTOR.version) == ("DET-BEACON", "1.0.0")


# ---- the score, on hand-computable series -----------------------------------------------
def scores(times: list[float], sizes: list[float] | None = None, span: float | None = None) -> Any:
    t = np.array(times, dtype=np.float64)
    b = np.array(sizes if sizes is not None else [100.0] * len(times), dtype=np.float64)
    return beacon_scores(t, b, span, CFG)


def test_perfect_series_scores_one() -> None:
    s = scores(series(30), span=1740.0)
    assert (s.s_disp, s.s_skew, s.s_size, s.s_cov, s.score) == (1.0, 1.0, 1.0, 1.0, 1.0)
    assert s.events == 30 and s.median_interval_s == 60.0 and s.mad_interval_s == 0.0


def test_dispersion_uses_the_median_absolute_deviation() -> None:
    # d = [8, 10, 12]: median 10, MAD = median(|d-10|) = 2 -> s_disp = 0.8; symmetric -> Bowley 0
    s = scores([0, 8, 18, 30], span=60.0)
    assert s.median_interval_s == 10 and s.mad_interval_s == 2
    assert s.s_disp == pytest.approx(0.8) and s.bowley == 0 and s.s_skew == 1.0


def test_one_outlier_gap_does_not_hurt_dispersion() -> None:
    s = scores([0, 10, 20, 30, 40, 140], span=140.0)  # d = [10, 10, 10, 10, 100]
    assert s.s_disp == 1.0  # MAD is robust to a single missed beat


def test_bowley_skewness_penalises_asymmetric_gaps() -> None:
    # d = [1, 1, 2, 10, 10]: Q1 1, Q2 2, Q3 10 -> b = (10 + 1 - 4) / 9 = 7/9
    s = scores(list(np.cumsum([0, 1, 1, 2, 10, 10])), span=100.0)
    assert s.bowley == pytest.approx(7 / 9) and s.s_skew == pytest.approx(2 / 9)


def test_size_regularity() -> None:
    assert scores(series(10), [100] * 10).s_size == 1.0
    assert scores(series(10), [0] * 10).s_size == 1.0  # identical sizes, even zero
    assert scores(series(3), [10, 20, 30]).s_size == pytest.approx(0.5)  # MAD 10, median 20
    assert scores(series(5), [0, 0, 0, 5, 9]).s_size == 0.0  # median 0, sizes differ


def test_coverage_is_the_observed_span_over_half_the_capture() -> None:
    assert scores(series(10, 10), span=900.0).s_cov == pytest.approx(90 / 450)
    assert scores(series(10, 10), span=100.0).s_cov == 1.0  # capped at 1
    assert scores(series(10, 10), span=None).s_cov == 1.0  # unknown span: observed span itself


def test_weights_are_applied() -> None:
    weights = CFG.weights.model_copy(
        update={"dispersion": 3.0, "skew": 0, "size": 0, "coverage": 0}
    )
    custom = CFG.model_copy(update={"weights": weights})
    t = np.array([0, 8, 18, 30.0])
    s = beacon_scores(t, np.array([1, 1000, 5, 50.0]), 60.0, custom)
    assert s.score == pytest.approx(s.s_disp)


def test_jittered_series_still_scores_well_and_random_series_does_not() -> None:
    jittered = scores(series(40, 60, jitter=0.2), span=2400.0)
    assert 0.8 <= jittered.score < 1.0
    rng = random.Random(7)  # noqa: S311
    times = list(np.cumsum([0.0] + [rng.expovariate(1 / 60) for _ in range(39)]))
    rand = scores(times, [rng.randint(50, 5000) for _ in range(40)], span=float(times[-1]))
    assert rand.score < 0.8


def test_zero_intervals_cannot_score_dispersion() -> None:
    assert scores([5, 5, 5, 5]).s_disp == 0.0


# ---- the detector -----------------------------------------------------------------------
def test_a_regular_beacon_fires_with_high_confidence_and_records_everything() -> None:
    [f] = run(beacon_conns(30)).findings
    assert (f.type, f.primary_entity, f.secondary_entities) == ("BEACON", SRC, [DST])
    assert f.confidence == "high" and f.severity_base == 4.0
    m = f.metrics
    assert m["series"] == "ip" and m["dst_port"] == 443 and m["events"] == 30
    assert m["beacon_score"] == 0.9917  # coverage 1740 / 1800 = 0.967, the other terms are 1.0
    assert m["median_interval_s"] == 60.0
    assert f.thresholds["min_score"] == 0.8 and f.thresholds["min_events"] == 10
    assert f.evidence_count == 30 and f.start_ts < f.end_ts


def test_ten_events_is_the_minimum_and_nine_is_silent() -> None:
    [f] = run(beacon_conns(10)).findings
    assert f.confidence == "medium"  # high needs >= 20 events
    assert run(beacon_conns(9)).findings == []


def test_confidence_boundaries() -> None:
    assert run(beacon_conns(19)).findings[0].confidence == "medium"
    assert run(beacon_conns(20)).findings[0].confidence == "high"


def test_score_threshold_boundary_with_coverage() -> None:
    # perfect timing and size, but only a sliver of the capture: coverage pulls the mean down
    low = run(beacon_conns(10, interval=10.0), span=7200.0)  # observed 90 s of a 7200 s capture
    assert low.findings == []  # mean(1, 1, 1, 0.025) = 0.756 < 0.8
    ok = run(beacon_conns(10, interval=10.0), span=300.0)
    assert len(ok.findings) == 1


def test_irregular_traffic_is_not_a_beacon() -> None:
    rng = random.Random(3)  # noqa: S311
    times = list(np.cumsum([0.0] + [rng.expovariate(1 / 30) for _ in range(59)]))
    sizes = [rng.randint(100, 20000) for _ in range(60)]
    rows = conn_rows(SRC, DST, times, 443, orig_bytes=sizes)
    assert run(rows, span=float(times[-1])).findings == []


def test_ports_in_the_periodic_allowlist_are_suppressed_but_counted() -> None:
    out = run(beacon_conns(30, port=123), network=context(allowlist={"periodic_ports": [123]}))
    assert out.findings == [] and out.suppressed == {"periodic_port": 1}
    assert len(run(beacon_conns(30, port=123)).findings) == 1  # default context has no allowlist


def test_external_sources_are_not_considered() -> None:
    rows = conn_rows("203.0.113.50", "10.0.0.9", series(30), 22)
    assert run(rows).findings == []


def test_a_beacon_over_changing_ips_is_found_through_the_tls_name() -> None:
    rows: list[dict[str, Any]] = []
    ssl: list[dict[str, Any]] = []
    for i, t in enumerate(series(20)):
        rows += conn_rows(SRC, f"198.51.100.{i + 1}", [t], 443, uid_prefix=f"R{i}")
        ssl.append({"ts": T0 + t, "uid": rows[-1]["uid"], "server_name": "Updates.Example.com"})
    [f] = run(rows, ssl=ssl).findings
    assert f.metrics["series"] == "name" and f.secondary_entities == ["updates.example.com"]
    assert f.metrics["events"] == 20


def test_a_name_series_covered_by_an_ip_series_is_not_reported_twice() -> None:
    rows = beacon_conns(30)
    ssl = [{"ts": r["ts"], "uid": r["uid"], "server_name": "c2.example.com"} for r in rows]
    [f] = run(rows, ssl=ssl).findings
    assert f.metrics["series"] == "ip"


def test_allowlisted_names_are_suppressed_and_counted() -> None:
    rows: list[dict[str, Any]] = []
    ssl: list[dict[str, Any]] = []
    for i, t in enumerate(series(20)):
        rows += conn_rows(SRC, f"198.51.100.{i + 1}", [t], 443, uid_prefix=f"R{i}")
        ssl.append({"ts": T0 + t, "uid": rows[-1]["uid"], "server_name": "telemetry.vendor.com"})
    out = run(rows, ssl=ssl, network=context(allowlist={"domains": ["vendor.com"]}))
    assert out.findings == [] and out.suppressed == {"allowlisted_domain": 1}


def test_http_requests_on_one_connection_are_found_from_http_log_timestamps() -> None:
    one_conn = conn_rows(SRC, DST, [0.0], 80, duration=1800.0)
    http = [
        {
            "ts": T0 + t,
            "uid": one_conn[0]["uid"],
            "orig_h": SRC,
            "resp_h": DST,
            "resp_p": 80,
            "trans_depth": i + 1,
            "request_body_len": 0,
            "response_body_len": 512,
        }
        for i, t in enumerate(series(20, 30.0))
    ]
    [f] = run(one_conn, http=http).findings
    assert f.metrics["series"] == "http_requests" and f.metrics["events"] == 20


def test_empty_tables_and_determinism() -> None:
    assert DETECTOR.run(detector_input()).findings == []
    rows = beacon_conns(25, jitter=0.05)
    a = [f.model_dump() for f in run(rows).findings]
    b = [f.model_dump() for f in run(list(reversed(rows))).findings]
    assert a == b and len(a) == 1
