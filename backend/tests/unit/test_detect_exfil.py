"""DET-EXFIL. All inputs are SYNTHETIC evidence tables (tests/detect_helpers.py)."""

from typing import Any

import numpy as np
import pytest

from app.detect.base import DetectorOutput
from app.detect.exfil import DETECTOR, modified_z
from tests.detect_helpers import T0, conn_rows, context, detector_input, frame, tables

SRC = "10.0.0.5"
MB = 1_000_000


def run(rows: list[dict[str, Any]], **kw: Any) -> DetectorOutput:
    given = {"conn": frame("conn", rows)}
    given.update({k: frame(k, v) for k, v in kw.pop("tbl", {}).items()})
    return DETECTOR.run(detector_input(tables(**given), **kw))


def population(n: int, src: str = SRC) -> list[dict[str, Any]]:
    """n small, slightly different internal->external pairs (the baseline)."""
    rows: list[dict[str, Any]] = []
    for i in range(n):
        rows += conn_rows(
            src,
            f"203.0.113.{i + 1}",
            [float(i)],
            443,
            orig_bytes=100_000 + i * 7_000,
            resp_bytes=50_000,
            uid_prefix=f"P{i}",
        )
    return rows


def big(out_bytes: int, in_bytes: int = 1 * MB, dst: str = "198.51.100.7") -> list[dict[str, Any]]:
    return conn_rows(
        SRC, dst, [100.0], 443, orig_bytes=out_bytes, resp_bytes=in_bytes, uid_prefix="BIG"
    )


def test_identity() -> None:
    assert (DETECTOR.detector_id, DETECTOR.version) == ("DET-EXFIL", "1.0.0")


# ---- the modified z-score ---------------------------------------------------------------
def test_modified_z_on_a_known_sample() -> None:
    z = modified_z(np.array([1.0, 2.0, 3.0, 4.0, 100.0]))  # median 3, MAD 1
    assert z[2] == 0.0 and z[4] == pytest.approx(0.6745 * 97)
    assert z[0] == pytest.approx(0.6745 * -2)


def test_modified_z_with_a_zero_mad_uses_the_mean_absolute_deviation_fallback() -> None:
    z = modified_z(np.array([5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 9.0]))  # MAD = 0
    assert z[0] == 0.0
    assert z[6] == pytest.approx(4 / (1.253314 * (4 / 7)))
    assert modified_z(np.array([7.0, 7.0, 7.0])).tolist() == [0.0, 0.0, 0.0]  # no spread at all


# ---- firing with a real baseline (>= 20 pairs) ------------------------------------------
def test_a_large_outlier_fires_with_high_confidence_and_records_everything() -> None:
    [f] = run(population(24) + big(60 * MB)).findings
    assert (f.type, f.primary_entity, f.secondary_entities) == ("EXFIL", SRC, ["198.51.100.7"])
    assert f.confidence == "high" and f.severity_base == 5.0
    m = f.metrics
    assert m["outbound_bytes"] == 60 * MB and m["inbound_bytes"] == MB and m["out_in_ratio"] == 60.0
    assert m["pairs_in_population"] == 25 and m["weak_baseline"] is False and m["grouping"] == "ip"
    assert m["modified_z"] > 3.5  # type: ignore[operator]
    assert f.thresholds["min_outbound_bytes"] == 50_000_000 and f.evidence_count == 1


def test_the_byte_floor_is_inclusive_at_fifty_million() -> None:
    assert len(run(population(24) + big(50_000_000)).findings) == 1
    assert run(population(24) + big(49_999_999)).findings == []


def test_the_out_in_ratio_must_be_at_least_five() -> None:
    assert len(run(population(24) + big(60 * MB, in_bytes=12 * MB)).findings) == 1  # exactly 5
    assert run(population(24) + big(60 * MB, in_bytes=12 * MB + 1)).findings == []  # just under


def test_a_population_of_equally_heavy_pairs_has_no_outlier() -> None:
    rows: list[dict[str, Any]] = []
    for i in range(25):
        rows += conn_rows(
            SRC,
            f"198.51.100.{i + 1}",
            [float(i)],
            443,
            orig_bytes=60 * MB,
            resp_bytes=MB,
            uid_prefix=f"H{i}",
        )
    assert run(rows).findings == []  # z = 0 for everyone: backup-like fleets are not unusual


def test_ordinary_traffic_is_silent() -> None:
    assert run(population(30)).findings == []


# ---- weak baseline (< 20 pairs) ---------------------------------------------------------
def test_with_fewer_than_twenty_pairs_only_the_floor_applies_at_low_confidence() -> None:
    [f] = run(population(3) + big(60 * MB, in_bytes=70 * MB)).findings  # ratio < 1 is not checked
    assert f.confidence == "low"
    assert f.metrics["weak_baseline"] is True and f.metrics["modified_z"] is None
    assert f.metrics["pairs_in_population"] == 4


def test_nineteen_pairs_is_weak_and_twenty_is_a_baseline() -> None:
    weak = run(population(18) + big(60 * MB)).findings[0]
    strong = run(population(19) + big(60 * MB)).findings[0]
    assert weak.confidence == "low" and strong.confidence == "high"


# ---- suppression and scope --------------------------------------------------------------
def test_backup_servers_are_suppressed_but_counted() -> None:
    out = run(
        population(24) + big(60 * MB, dst="198.51.100.7"),
        network=context(known_hosts={"backup_servers": ["198.51.100.7"]}),
    )
    assert out.findings == [] and out.suppressed == {"backup_server": 1}


def test_internal_destinations_and_external_sources_are_not_outbound() -> None:
    internal = conn_rows(SRC, "10.0.9.9", [0.0], 873, orig_bytes=90 * MB, resp_bytes=1)
    inbound_initiated = conn_rows("203.0.113.9", SRC, [0.0], 8080, orig_bytes=90 * MB, resp_bytes=1)
    assert run(population(24) + internal + inbound_initiated).findings == []


def test_null_byte_counts_are_treated_as_zero() -> None:
    rows = population(24) + big(60 * MB)
    rows[0]["orig_bytes"] = None
    rows[1]["resp_bytes"] = None
    assert len(run(rows).findings) == 1


def test_bytes_accumulate_across_connections_of_the_same_pair() -> None:
    parts = conn_rows(
        SRC,
        "198.51.100.7",
        [100.0, 200.0, 300.0],
        443,
        orig_bytes=20 * MB,
        resp_bytes=MB,
        duration=5.0,
        uid_prefix="X",
    )
    [f] = run(population(24) + parts).findings
    assert f.metrics["outbound_bytes"] == 60 * MB and f.metrics["connections"] == 3
    assert f.start_ts.timestamp() == pytest.approx(
        T0 + 100
    ) and f.end_ts.timestamp() == pytest.approx(T0 + 305)


# ---- grouping by name -------------------------------------------------------------------
def test_a_destination_that_rotates_ips_is_found_through_its_tls_name() -> None:
    rows: list[dict[str, Any]] = []
    ssl: list[dict[str, Any]] = []
    for i in range(10):
        rows += conn_rows(
            SRC,
            f"198.51.100.{i + 1}",
            [float(i)],
            443,
            orig_bytes=8 * MB,
            resp_bytes=10_000,
            uid_prefix=f"R{i}",
        )
        ssl.append({"ts": T0 + i, "uid": rows[-1]["uid"], "server_name": "Upload.Example.com"})
    [f] = run(rows, tbl={"ssl": ssl}).findings
    assert f.metrics["grouping"] == "name" and f.secondary_entities == ["upload.example.com"]
    assert f.metrics["outbound_bytes"] == 80 * MB


def test_a_name_grouping_already_covered_by_an_ip_finding_is_not_reported_twice() -> None:
    rows = big(60 * MB)
    ssl = [{"ts": T0 + 100, "uid": rows[0]["uid"], "server_name": "up.example.com"}]
    [f] = run(rows, tbl={"ssl": ssl}).findings
    assert f.metrics["grouping"] == "ip"


def test_empty_tables_and_determinism() -> None:
    assert DETECTOR.detector_id and DETECTOR.run(detector_input()).findings == []
    rows = population(24) + big(60 * MB)
    a = [f.model_dump() for f in run(rows).findings]
    b = [f.model_dump() for f in run(list(reversed(rows))).findings]
    assert a == b and len(a) == 1
