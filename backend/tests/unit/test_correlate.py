"""Correlation: grouping, links, severity. SYNTHETIC findings only (tests/detect_helpers.py)."""

from pathlib import Path

import pytest

from app.core.errors import ConfigError
from app.correlate.config import CorrelationConfig, load_correlation_config
from app.correlate.incidents import group_findings
from app.correlate.runner import correlate
from app.correlate.severity import finding_score, incident_score, label
from app.detect.base import Finding
from tests.detect_helpers import finding

CONFIG = Path(__file__).resolve().parents[3] / "config" / "correlation.yaml"
CFG: CorrelationConfig = load_correlation_config(CONFIG)
GAP = 1800.0
A, B, C = "10.0.0.5", "10.0.0.9", "10.0.0.7"


def f(
    fid: str, type_: str, primary: str, start: float, end: float | None = None, **kw: object
) -> Finding:
    return finding(type_, primary, start, end, fid=fid, **kw)


def test_shipped_config_matches_architecture_section_nine() -> None:
    s = CFG.severity
    assert CFG.gap_s == 1800 and s.cap == 10
    assert s.base == {
        "SCAN": 2,
        "BRUTE": 3,
        "DNSTUN": 4,
        "BEACON": 4,
        "EXFIL": 5,
        "UNEXPLAINED_ANOMALY": 1,
    }
    assert (s.weight.low, s.weight.medium, s.weight.high) == (0.5, 0.75, 1.0)
    assert (s.extra_type_bonus, s.link_bonus) == (0.5, 1.0)
    assert (s.buckets.low, s.buckets.medium, s.buckets.high) == (2.5, 4.5, 6.5)


def test_invalid_config_is_a_config_error(tmp_path: Path) -> None:
    (tmp_path / "c.yaml").write_text("version: 1\ngap_s: -5\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_correlation_config(tmp_path / "c.yaml")
    with pytest.raises(ConfigError):
        load_correlation_config(tmp_path / "missing.yaml")


# ---- grouping ---------------------------------------------------------------------------
def test_findings_within_the_gap_join_one_incident_and_beyond_it_start_a_new_one() -> None:
    items = [
        f("F-1", "SCAN", A, 0, 100),
        f("F-2", "BRUTE", A, 100 + GAP),
        f("F-3", "SCAN", A, 100 + GAP + 100 + GAP + 1),
    ]
    groups = group_findings(items, GAP)
    assert [g.finding_ids for g in groups] == [
        ("F-1", "F-2"),
        ("F-3",),
    ]  # F-2 starts exactly at end + gap


def test_the_gap_is_measured_from_the_running_incident_end_not_the_last_start() -> None:
    items = [f("F-1", "SCAN", A, 0, 5000), f("F-2", "BRUTE", A, 5000 + GAP - 1)]
    assert len(group_findings(items, GAP)) == 1  # joined because F-1 lasted until 5000


def test_a_long_finding_extends_the_incident_for_later_ones() -> None:
    items = [
        f("F-1", "SCAN", A, 0, 10),
        f("F-2", "BEACON", A, 10 + GAP, 10 + GAP + 4000),
        f("F-3", "EXFIL", A, 10 + GAP + 4000 + GAP),
    ]
    assert [g.finding_ids for g in group_findings(items, GAP)] == [("F-1", "F-2", "F-3")]


def test_each_primary_entity_gets_its_own_incidents_ordered_by_start() -> None:
    items = [f("F-1", "SCAN", B, 50), f("F-2", "SCAN", A, 10), f("F-3", "SCAN", A, 20)]
    groups = group_findings(items, GAP)
    assert [(g.primary_entity, g.finding_ids) for g in groups] == [
        (A, ("F-2", "F-3")),
        (B, ("F-1",)),
    ]


def test_no_findings_no_incidents() -> None:
    assert correlate([], CFG).incidents == [] and group_findings([], GAP) == []


# ---- severity ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("type_", "confidence", "expected"),
    [
        ("EXFIL", "high", 5.0),
        ("EXFIL", "low", 2.5),
        ("SCAN", "medium", 1.5),
        ("BEACON", "high", 4.0),
    ],
)
def test_finding_score(type_: str, confidence: str, expected: float) -> None:
    assert finding_score(type_, confidence, CFG.severity) == expected


def test_incident_score_worked_examples() -> None:
    s = CFG.severity
    assert incident_score([2.0], 1, False, s) == (
        2.0,
        {"max_finding_score": 2.0, "type_bonus": 0.0, "link_bonus": 0.0},
    )
    assert incident_score([3.0, 5.0], 2, False, s)[0] == 5.5  # 5 + 0.5
    assert incident_score([4.0, 5.0, 2.0], 3, True, s)[0] == 7.0  # 5 + 1.0 + 1.0
    assert incident_score([5.0, 5.0], 5, True, s)[0] == 8.0  # 5 + 2.0 + 1.0
    assert incident_score([9.5], 5, True, s)[0] == 10.0  # capped


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "low"),
        (2.49, "low"),
        (2.5, "medium"),
        (4.49, "medium"),
        (4.5, "high"),
        (6.49, "high"),
        (6.5, "critical"),
        (10.0, "critical"),
    ],
)
def test_bucket_boundaries(score: float, expected: str) -> None:
    assert label(score, CFG.severity) == expected


# ---- links ------------------------------------------------------------------------------
def test_target_later_active_links_the_brute_incident_to_the_targets_later_incident() -> None:
    items = [
        f("F-1", "BRUTE", A, 100, 200, secondary=[B]),
        f("F-2", "BEACON", B, 5000, 5100, secondary=["203.0.113.9"]),
    ]
    result = correlate(items, CFG)
    [link] = [lk for lk in result.links if lk.type == "TARGET_LATER_ACTIVE"]
    assert (link.from_incident, link.to_incident, link.finding_ids) == ("I-1", "I-2", ["F-1"])
    by_id = {i.id: i for i in result.incidents}
    assert by_id["I-2"].severity_breakdown["link_bonus"] == 1.0  # target side
    assert by_id["I-1"].severity_breakdown["link_bonus"] == 0.0


def test_target_later_active_needs_the_target_incident_to_start_after_the_brute_finding() -> None:
    before = [f("F-1", "BRUTE", A, 1000, 1100, secondary=[B]), f("F-2", "BEACON", B, 10, 20)]
    assert not [lk for lk in correlate(before, CFG).links if lk.type == "TARGET_LATER_ACTIVE"]
    other_host = [f("F-1", "BRUTE", A, 100, 200, secondary=[B]), f("F-2", "BEACON", C, 5000, 5100)]
    assert not [lk for lk in correlate(other_host, CFG).links if lk.type == "TARGET_LATER_ACTIVE"]


def test_shared_external_peer_links_beacon_and_exfil_to_the_same_destination() -> None:
    items = [
        f("F-1", "BEACON", A, 0, 100, secondary=["203.0.113.9"]),
        f("F-2", "EXFIL", B, 50, 90, secondary=["203.0.113.9"]),
    ]
    result = correlate(items, CFG)
    [link] = [lk for lk in result.links if lk.type == "SHARED_EXTERNAL_PEER"]
    assert link.finding_ids == ["F-1", "F-2"] and result.exfil_with_beacon == {"F-2"}
    assert all(i.severity_breakdown["link_bonus"] == 1.0 for i in result.incidents)


def test_shared_peer_in_one_incident_makes_no_link_row_but_still_marks_t1041_and_severity() -> None:
    items = [
        f("F-1", "BEACON", A, 0, 100, secondary=["x.example.com"]),
        f("F-2", "EXFIL", A, 50, 90, secondary=["x.example.com"]),
    ]
    result = correlate(items, CFG)
    assert [lk for lk in result.links if lk.type == "SHARED_EXTERNAL_PEER"] == []
    assert (
        result.exfil_with_beacon == {"F-2"}
        and result.incidents[0].severity_breakdown["link_bonus"] == 1.0
    )


def test_different_destinations_do_not_link() -> None:
    items = [
        f("F-1", "BEACON", A, 0, 100, secondary=["203.0.113.9"]),
        f("F-2", "EXFIL", B, 0, 100, secondary=["203.0.113.10"]),
    ]
    result = correlate(items, CFG)
    assert result.links == [] and result.exfil_with_beacon == frozenset()


def test_same_actor_later_links_consecutive_incidents_of_one_entity() -> None:
    items = [
        f("F-1", "SCAN", A, 0, 10),
        f("F-2", "SCAN", A, 10 + GAP + 1, 10 + GAP + 2),
        f("F-3", "SCAN", A, 99999, 100000),
    ]
    links = [lk for lk in correlate(items, CFG).links if lk.type == "SAME_ACTOR_LATER"]
    assert [(lk.from_incident, lk.to_incident) for lk in links] == [("I-1", "I-2"), ("I-2", "I-3")]
    assert correlate([f("F-1", "SCAN", A, 0, 10)], CFG).links == []


def test_the_multi_stage_storyline_yields_both_documented_links() -> None:
    """scan -> brute force -> the target beacons and uploads to the same destination."""
    items = [
        f("F-1", "SCAN", "198.51.100.1", 0, 60, secondary=[B], confidence="high"),
        f("F-2", "BRUTE", "198.51.100.1", 120, 400, secondary=[B], confidence="high"),
        f("F-3", "BEACON", B, 3000, 3600, secondary=["203.0.113.9"], confidence="high"),
        f("F-4", "EXFIL", B, 3700, 3900, secondary=["203.0.113.9"], confidence="high"),
    ]
    result = correlate(items, CFG)
    assert [i.id for i in result.incidents] == ["I-1", "I-2"]
    assert {lk.type for lk in result.links} == {
        "TARGET_LATER_ACTIVE"
    }  # same incident for the peer pair
    assert result.exfil_with_beacon == {"F-4"}
    first, second = result.incidents
    assert first.types == ["BRUTE", "SCAN"] and second.types == ["BEACON", "EXFIL"]
    assert first.severity_score == 3.0 + 0.5 and second.severity_score == 5.0 + 0.5 + 1.0


def test_output_is_deterministic_and_independent_of_input_order() -> None:
    items = [
        f("F-1", "BRUTE", A, 100, 200, secondary=[B]),
        f("F-2", "BEACON", B, 5000, 5100, secondary=["203.0.113.9"]),
        f("F-3", "EXFIL", C, 5000, 5100, secondary=["203.0.113.9"]),
        f("F-4", "SCAN", A, 10, 20),
    ]
    a = correlate(items, CFG)
    b = correlate(list(reversed(items)), CFG)
    assert [i.model_dump_json() for i in a.incidents] == [i.model_dump_json() for i in b.incidents]
    assert [lk.model_dump_json() for lk in a.links] == [lk.model_dump_json() for lk in b.links]
