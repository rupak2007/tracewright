"""Finding-to-episode matching (eval/PROTOCOL.md §3). SYNTHETIC episodes and findings only."""

from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("eval")
pytest.importorskip("lab")

from eval.matching import (
    FindingView,
    RunEvaluation,
    evaluate_run,
    matches,
    ratio,
    summarise,
    time_matches,
)
from lab.schema import Episode

T0 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)
ACTOR, TARGET, OTHER = "10.0.0.5", "10.0.0.9", "10.0.0.77"


def episode(
    kind: str = "attack",
    cls: str = "SCAN",
    start: int = 100,
    end: int = 200,
    actor: str = ACTOR,
    targets: tuple[str, ...] = (TARGET,),
    eid: str = "r1-e1",
) -> Episode:
    return Episode(
        run_id="r1",
        episode_id=eid,
        kind=kind,
        cls=cls,
        actor=actor,
        targets=targets,
        start=T0 + timedelta(seconds=start),
        end=T0 + timedelta(seconds=end),
    )


def finding(
    type_: str = "SCAN",
    primary: str = ACTOR,
    secondary: tuple[str, ...] = (TARGET,),
    start: int = 120,
    end: int = 150,
    confidence: str = "high",
    fid: str = "F-1",
) -> FindingView:
    return FindingView(
        fid,
        type_,
        primary,
        secondary,
        T0 + timedelta(seconds=start),
        T0 + timedelta(seconds=end),
        confidence,
    )


def test_a_finding_on_the_actor_in_time_with_the_right_class_matches() -> None:
    assert matches(finding(), episode())


def test_entity_rule_for_scan_and_brute_uses_actor_or_a_secondary_target() -> None:
    assert matches(finding(primary=OTHER, secondary=(TARGET,)), episode())  # target match
    assert not matches(finding(primary=OTHER, secondary=(OTHER,)), episode())
    brute = finding("BRUTE", primary=OTHER, secondary=(TARGET,))
    assert matches(brute, episode(cls="BRUTE"))


def test_entity_rule_for_host_centred_detectors_accepts_actor_or_target_as_primary() -> None:
    for cls in ("DNSTUN", "BEACON", "EXFIL"):
        assert matches(finding(cls, primary=ACTOR, secondary=()), episode(cls=cls))
        assert matches(finding(cls, primary=TARGET, secondary=()), episode(cls=cls))
        assert not matches(finding(cls, primary=OTHER, secondary=(TARGET,)), episode(cls=cls))


def test_time_window_is_the_episode_plus_or_minus_sixty_seconds_inclusive() -> None:
    e = episode(start=100, end=200)
    assert time_matches(finding(start=0, end=40), e)  # ends exactly 60 s before the start
    assert not time_matches(finding(start=0, end=39), e)
    assert time_matches(finding(start=260, end=300), e)  # starts exactly 60 s after the end
    assert not time_matches(finding(start=261, end=300), e)
    assert time_matches(finding(start=0, end=1000), e)  # a finding spanning the episode overlaps


def test_class_must_match_for_attacks_but_not_for_hard_negatives() -> None:
    assert not matches(finding("BEACON"), episode(cls="SCAN"))
    hard = episode(kind="hard_negative", cls="NTP")
    assert matches(finding("BEACON", primary=ACTOR, secondary=()), hard)


def test_evaluate_run_counts_detected_missed_and_false_positive_findings() -> None:
    episodes = [
        episode(cls="SCAN", eid="r1-e1"),
        episode(cls="BRUTE", eid="r1-e2", start=500, end=600),
    ]
    findings = [
        finding("SCAN", fid="F-1"),  # detects e1
        finding("EXFIL", primary=OTHER, secondary=(), start=900, end=910, fid="F-2"),  # FP
        finding("BEACON", primary=OTHER, secondary=(), confidence="low", fid="F-3"),  # low FP
    ]
    result = evaluate_run(findings, episodes)
    assert result.attack_episodes == {"SCAN": 1, "BRUTE": 1}
    assert result.detected == {"SCAN": 1}
    assert [fp[0] for fp in result.false_positives] == ["F-2", "F-3"]
    assert result.findings == 3


def test_a_false_positive_on_a_hard_negative_is_attributed_to_it() -> None:
    hard = episode(kind="hard_negative", cls="MONITORING_HEARTBEAT", actor=ACTOR)
    result = evaluate_run([finding("BEACON", primary=ACTOR, secondary=(TARGET,))], [hard])
    assert result.false_positives == [("F-1", "BEACON", "high", "MONITORING_HEARTBEAT")]
    unattributed = evaluate_run([finding("BEACON", primary=OTHER, secondary=())], [hard])
    assert unattributed.false_positives[0][3] is None


def test_summary_never_invents_a_metric_without_a_denominator() -> None:
    result = evaluate_run(
        [finding("BEACON", primary=ACTOR, secondary=())], [episode(kind="hard_negative", cls="NTP")]
    )
    s = summarise(result, benign_hours=2.0)
    assert s["recall"] is None and s["precision"] is None  # no attack episode exists
    assert s["false_positive_findings_medium_high"] == 1
    assert s["false_positives_per_benign_hour_medium_high"] == 0.5
    assert s["false_positive_by_hard_negative_medium_high"] == {"NTP": 1}
    assert (
        summarise(result, benign_hours=0.0)["false_positives_per_benign_hour_medium_high"] is None
    )


def test_summary_with_attacks_reports_recall_and_precision_and_filters_confidence() -> None:
    episodes = [
        episode(cls="SCAN", eid="r1-e1"),
        episode(cls="BRUTE", eid="r1-e2", start=500, end=600),
    ]
    findings = [
        finding("SCAN", fid="F-1"),
        finding("EXFIL", primary=OTHER, secondary=(), start=900, end=910, fid="F-2"),
        finding("BEACON", primary=OTHER, secondary=(), confidence="low", fid="F-3"),
    ]
    s = summarise(evaluate_run(findings, episodes), benign_hours=1.0)
    assert s["recall"] == 0.5 and s["precision"] == 1 / 3
    assert s["false_positive_findings_all_confidence"] == 2
    assert s["false_positive_findings_medium_high"] == 1  # the low-confidence one is not counted


def test_merge_and_ratio() -> None:
    a = evaluate_run([finding()], [episode()])
    b = evaluate_run([], [episode(cls="BRUTE", eid="r1-e2")])
    total = RunEvaluation()
    total.merge(a)
    total.merge(b)
    assert total.attack_episodes == {"SCAN": 1, "BRUTE": 1} and total.detected == {"SCAN": 1}
    assert ratio(1, 0) is None and ratio(1, 4) == 0.25


def episode_with(cls: str, params: dict[str, object], eid: str, start: int = 100) -> Episode:
    return Episode(
        run_id="r1",
        episode_id=eid,
        kind="attack",
        cls=cls,
        actor=ACTOR,
        targets=(TARGET,),
        start=T0 + timedelta(seconds=start),
        end=T0 + timedelta(seconds=start + 100),
        params=params,
    )


def test_brute_and_scan_are_reported_per_subpopulation_and_unlabelled_ones_are_not_hidden() -> None:
    from eval.matching import subgroup

    episodes = [
        episode_with("BRUTE", {"service": "ftp"}, "r1-e1", 100),
        episode_with("BRUTE", {"service": "HTTP"}, "r1-e2", 1000),
        episode_with("BRUTE", {"service": "ssh"}, "r1-e3", 2000),
        episode_with("BRUTE", {}, "r1-e4", 3000),
        episode_with("SCAN", {"speed": "slow"}, "r1-e5", 4000),
        episode_with("SCAN", {"speed": "default"}, "r1-e6", 5000),
        episode_with("BEACON", {}, "r1-e7", 6000),
    ]
    assert [subgroup(e) for e in episodes] == [
        "ftp_http",
        "ftp_http",
        "ssh_rdp_telnet",
        "unspecified",
        "slow",
        "default",
        None,
    ]
    hits = [  # detect the FTP and the slow scan only
        finding("BRUTE", start=120, end=150, fid="F-1"),
        finding("SCAN", start=4020, end=4050, fid="F-2"),
    ]
    summary = summarise(evaluate_run(hits, episodes), benign_hours=0.0)
    sub = summary["per_subpopulation"]
    assert sub["BRUTE/ftp_http"] == {"episodes": 2, "detected": 1, "recall": 0.5}
    assert sub["BRUTE/ssh_rdp_telnet"] == {"episodes": 1, "detected": 0, "recall": 0.0}
    assert sub["BRUTE/unspecified"]["episodes"] == 1
    assert sub["SCAN/slow"]["recall"] == 1.0 and sub["SCAN/default"]["recall"] == 0.0
    assert "BEACON/None" not in sub and not any(k.startswith("BEACON") for k in sub)


def test_per_class_precision_and_recall_have_no_denominator_games() -> None:
    episodes = [episode_with("SCAN", {"speed": "default"}, "r1-e1", 100)]
    hits = [finding("SCAN", fid="F-1"), finding("SCAN", primary=OTHER, secondary=(), fid="F-2")]
    per_class = summarise(evaluate_run(hits, episodes), benign_hours=1.0)["per_class"]
    assert per_class["SCAN"] == {
        "episodes": 1,
        "detected": 1,
        "recall": 1.0,
        "findings": 2,
        "matched_findings": 1,
        "precision": 0.5,
    }
    empty = summarise(evaluate_run([finding("BEACON", primary=OTHER, secondary=())], []), 1.0)
    assert empty["per_class"]["BEACON"]["recall"] is None  # no episodes: not 0
    assert empty["per_class"]["BEACON"]["precision"] == 0.0  # a finding that matched nothing
