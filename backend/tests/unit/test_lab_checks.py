from datetime import UTC, datetime, timedelta

import pandas as pd
import pytest

pytest.importorskip("lab")

from lab.checks import check_episode, check_run
from lab.schema import Episode

T0 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)
ACTOR, TARGET, OTHER = "172.20.0.101", "172.20.0.20", "172.20.0.102"


def conn(*rows: tuple[float, str, str]) -> pd.DataFrame:
    """rows: (seconds after T0, orig_h, resp_h)"""
    return pd.DataFrame(
        {
            "ts": pd.to_datetime([T0 + timedelta(seconds=s) for s, _, _ in rows], utc=True),
            "orig_h": [o for _, o, _ in rows],
            "resp_h": [r for _, _, r in rows],
        }
    )


def episode(
    start_s: float = 10, end_s: float = 20, run_id: str = "r001", eid: str = "r001-e1"
) -> Episode:
    return Episode(
        run_id=run_id,
        episode_id=eid,
        kind="hard_negative",
        cls="NTP",
        actor=ACTOR,
        targets=(TARGET,),
        start=T0 + timedelta(seconds=start_s),
        end=T0 + timedelta(seconds=end_s),
    )


def test_forward_and_backward_connections_both_count() -> None:
    assert check_episode(episode(), conn((12, ACTOR, TARGET))).ok
    assert check_episode(episode(), conn((12, TARGET, ACTOR))).ok


def test_counts_matching_connections() -> None:
    result = check_episode(
        episode(), conn((11, ACTOR, TARGET), (12, ACTOR, TARGET), (13, OTHER, TARGET))
    )
    assert result.ok and result.matching_connections == 2


def test_tolerance_boundaries() -> None:
    assert check_episode(episode(), conn((10 - 5, ACTOR, TARGET)), tolerance_s=5).ok
    assert check_episode(episode(), conn((20 + 5, ACTOR, TARGET)), tolerance_s=5).ok
    outside = check_episode(episode(), conn((10 - 5.5, ACTOR, TARGET)), tolerance_s=5)
    assert not outside.ok and "not within the labelled time range" in outside.reason


def test_actor_absent_and_actor_without_target_are_distinguished() -> None:
    absent = check_episode(episode(), conn((12, OTHER, TARGET)))
    assert not absent.ok and absent.reason == "actor does not appear in the capture"
    lonely = check_episode(episode(), conn((12, ACTOR, OTHER)))
    assert not lonely.ok and "never with a labelled target" in lonely.reason


def test_empty_capture_fails() -> None:
    assert not check_episode(episode(), conn()).ok


def test_check_run_clean() -> None:
    frame = conn((12, ACTOR, TARGET))
    first, last = T0.timestamp(), (T0 + timedelta(seconds=30)).timestamp()
    assert check_run([episode()], "r001", frame, first, last) == []


def test_check_run_reports_every_kind_of_problem() -> None:
    frame = conn((12, ACTOR, TARGET))
    first, last = T0.timestamp(), (T0 + timedelta(seconds=30)).timestamp()
    episodes = [
        episode(),
        episode(),  # duplicate id
        episode(run_id="r002", eid="r002-e1"),  # other run's label in this file
        episode(start_s=500, end_s=510, eid="r001-e9"),  # outside capture span and no traffic
    ]
    problems = check_run(episodes, "r001", frame, first, last)
    joined = "\n".join(problems)
    assert "duplicate episode_id r001-e1" in joined
    assert "belongs to run r002" in joined
    assert "r001-e9: outside the capture's time span" in joined
    assert "r001-e9: actor and target talk in this capture, but not within" in joined


def test_check_run_without_capture_span_skips_only_the_span_check() -> None:
    assert check_run([episode()], "r001", conn((12, ACTOR, TARGET)), None, None) == []


def test_capture_gaps_on_episode_connections_fail_the_run() -> None:
    frame = conn((12, ACTOR, TARGET), (14, ACTOR, OTHER))
    frame["missed_bytes"] = [0, 0]
    first, last = T0.timestamp(), (T0 + timedelta(seconds=30)).timestamp()
    assert check_run([episode()], "r001", frame, first, last) == []
    frame["missed_bytes"] = [4096, 0]
    problems = check_run([episode()], "r001", frame, first, last)
    assert len(problems) == 1 and "4096 missed bytes" in problems[0]
    frame["missed_bytes"] = [0, 4096]  # a gap on an unrelated connection is not this episode's
    assert check_run([episode()], "r001", frame, first, last) == []
