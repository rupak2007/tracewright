"""Label-vs-capture consistency checks (plan P2: `lab/check_labels.py`).

Pure functions of the labels and of the Zeek `conn` table that `tracewright analyze` produced for
the same capture. They answer one question per episode: did traffic between the labelled actor and
a labelled target actually appear in the capture during the labelled time range?
"""

from dataclasses import dataclass
from datetime import timedelta

import pandas as pd

from lab.schema import Episode


@dataclass(frozen=True)
class EpisodeCheck:
    episode_id: str
    ok: bool
    reason: str
    matching_connections: int


def check_episode(episode: Episode, conn: pd.DataFrame, tolerance_s: float = 5.0) -> EpisodeCheck:
    """Passes when >= 1 conn row links the actor and a target (either direction) within
    [start - tolerance, end + tolerance]. The tolerance absorbs clock skew between containers."""
    lo = pd.Timestamp(episode.start - timedelta(seconds=tolerance_s))
    hi = pd.Timestamp(episode.end + timedelta(seconds=tolerance_s))
    in_range = (conn["ts"] >= lo) & (conn["ts"] <= hi)
    targets = list(episode.targets)
    forward = (conn["orig_h"] == episode.actor) & conn["resp_h"].isin(targets)
    backward = (conn["resp_h"] == episode.actor) & conn["orig_h"].isin(targets)
    count = int((in_range & (forward | backward)).sum())
    if count:
        return EpisodeCheck(episode.episode_id, True, "ok", count)
    seen_anywhere = int((forward | backward).sum())
    if seen_anywhere:
        reason = "actor and target talk in this capture, but not within the labelled time range"
    elif (conn["orig_h"] == episode.actor).any() or (conn["resp_h"] == episode.actor).any():
        reason = "actor appears in the capture but never with a labelled target"
    else:
        reason = "actor does not appear in the capture"
    return EpisodeCheck(episode.episode_id, False, reason, 0)


def check_run(
    episodes: list[Episode],
    run_id: str,
    conn: pd.DataFrame,
    capture_first_ts: float | None,
    capture_last_ts: float | None,
    tolerance_s: float = 5.0,
) -> list[str]:
    """Return a list of problems (empty means the run's labels are consistent with its capture)."""
    problems: list[str] = []
    ids = [e.episode_id for e in episodes]
    problems += [f"duplicate episode_id {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    for episode in episodes:
        if episode.run_id != run_id:
            problems.append(f"{episode.episode_id}: belongs to run {episode.run_id}, not {run_id}")
        if capture_first_ts is not None and capture_last_ts is not None:
            first = pd.Timestamp(capture_first_ts, unit="s", tz="UTC")
            last = pd.Timestamp(capture_last_ts, unit="s", tz="UTC")
            slack = pd.Timedelta(seconds=tolerance_s)
            if (
                pd.Timestamp(episode.end) < first - slack
                or pd.Timestamp(episode.start) > last + slack
            ):
                problems.append(f"{episode.episode_id}: outside the capture's time span")
        result = check_episode(episode, conn, tolerance_s)
        if not result.ok:
            problems.append(f"{episode.episode_id}: {result.reason}")
    return problems
