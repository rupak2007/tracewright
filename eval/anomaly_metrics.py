"""Anomaly-gate metrics and the pre-declared G1 rule (eval/PROTOCOL.md §6-7). Pure functions.

A scored window is POSITIVE when it overlaps (same host as the episode actor or a target, time
overlap of the window with the episode +- 60 s) a LAB-HOLDOUT episode. Per capture, windows are
ranked by score:
  precision@k   share of the top-k rule-unexplained windows that are positive
  recall@k      share of that capture's holdout episodes touched by a top-k window
  PR-AUC        average precision over the capture's rule-unexplained windows
The bootstrap resamples CAPTURES (not windows) with replacement. `decide_g1` is the PRD §11 rule,
verbatim; it only ever returns a decision from numbers it is given.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

import numpy as np
from lab.schema import Episode
from sklearn.metrics import average_precision_score

TOLERANCE = timedelta(seconds=60)
Decision = Literal["iforest", "robust_z", "off"]
BENIGN_RATE_LIMIT = 0.01
IFOREST_MARGIN = 0.10
ROBUST_MIN_RECALL = 0.5


@dataclass(frozen=True)
class WindowRef:
    host: str
    start: float  # epoch seconds
    end: float
    score: float
    rule_explained: bool


def window_is_positive(w: WindowRef, episodes: Sequence[Episode]) -> bool:
    for e in episodes:
        if w.host != e.actor and w.host not in e.targets:
            continue
        if (
            w.start <= (e.end + TOLERANCE).timestamp()
            and w.end >= (e.start - TOLERANCE).timestamp()
        ):
            return True
    return False


def top_k(windows: Sequence[WindowRef], k: int) -> list[WindowRef]:
    """Rule-unexplained windows by descending score (ties: earlier start, then host)."""
    pool = [w for w in windows if not w.rule_explained]
    return sorted(pool, key=lambda w: (-w.score, w.start, w.host))[:k]


def precision_at_k(
    windows: Sequence[WindowRef], episodes: Sequence[Episode], k: int = 10
) -> float | None:
    chosen = top_k(windows, k)
    if not chosen:
        return None
    return sum(window_is_positive(w, episodes) for w in chosen) / len(chosen)


def recall_at_k(
    windows: Sequence[WindowRef], episodes: Sequence[Episode], k: int = 10
) -> float | None:
    if not episodes:
        return None
    chosen = top_k(windows, k)
    return sum(any(window_is_positive(w, [e]) for w in chosen) for e in episodes) / len(episodes)


def pr_auc(windows: Sequence[WindowRef], episodes: Sequence[Episode]) -> float | None:
    pool = [w for w in windows if not w.rule_explained]
    labels = [window_is_positive(w, episodes) for w in pool]
    if not pool or not any(labels):
        return None
    return float(average_precision_score(labels, [w.score for w in pool]))


def promoted_rate(scores: Sequence[float], threshold: float | None) -> float | None:
    """Share of (benign) windows at or above the promotion threshold; None without a threshold."""
    if threshold is None or not scores:
        return None
    return sum(s >= threshold for s in scores) / len(scores)


def bootstrap_difference(
    a: Sequence[float], b: Sequence[float], samples: int = 1000, seed: int = 20261004
) -> tuple[float, float, float] | None:
    """Mean difference a - b over resampled captures: (mean, 2.5th, 97.5th percentile)."""
    if len(a) != len(b) or not a:
        return None
    x, y = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(x), size=(samples, len(x)))
    diffs = (x[idx] - y[idx]).mean(axis=1)
    return (
        float((x - y).mean()),
        float(np.percentile(diffs, 2.5)),
        float(np.percentile(diffs, 97.5)),
    )


def decide_g1(
    iforest_p10: float | None,
    robust_p10: float | None,
    diff_ci: tuple[float, float, float] | None,
    iforest_benign_rate: float | None,
    robust_recall10: float | None,
    robust_benign_rate: float | None,
) -> tuple[Decision, str]:
    """PRD §11 decision gate G1, applied to measured numbers (None = not measured).

    Ship `iforest` if its precision@10 exceeds robust_z's by >= 0.10 absolute, the 95% bootstrap
    CI of the difference excludes 0 and its benign promoted rate is <= 1%. Otherwise ship
    `robust_z` if its recall@10 of held-out episodes is >= 0.5 and its benign promoted rate is
    <= 1%. Otherwise `off`.
    """
    if (
        iforest_p10 is not None
        and robust_p10 is not None
        and diff_ci is not None
        and iforest_benign_rate is not None
        and iforest_p10 - robust_p10 >= IFOREST_MARGIN
        and diff_ci[1] > 0
        and iforest_benign_rate <= BENIGN_RATE_LIMIT
    ):
        return "iforest", "iforest beats robust_z by the required margin with a CI excluding 0"
    if (
        robust_recall10 is not None
        and robust_benign_rate is not None
        and robust_recall10 >= ROBUST_MIN_RECALL
        and robust_benign_rate <= BENIGN_RATE_LIMIT
    ):
        return "robust_z", "robust_z recall@10 and benign promoted rate meet the thresholds"
    return (
        "off",
        "neither scorer met its gate condition on the measured numbers (or none were measured)",
    )
