"""Sliding-window helpers over sorted event times (seconds). Windows are closed intervals:
events at distance exactly `window_s` from the first one are inside."""

from collections import Counter
from collections.abc import Hashable, Sequence

import numpy as np
from numpy.typing import NDArray


def max_distinct_window(
    times: NDArray[np.float64], values: Sequence[Hashable], window_s: float
) -> tuple[int, int, int]:
    """Window with the most distinct `values`: (distinct, lo, hi), events lo..hi-1 (hi exclusive).

    `times` must be sorted ascending. Ties go to the earliest window, so results are repeatable.
    """
    best, best_lo, best_hi = 0, 0, 0
    counts: Counter[Hashable] = Counter()
    lo = 0
    for hi in range(len(times)):
        counts[values[hi]] += 1
        while times[hi] - times[lo] > window_s:
            counts[values[lo]] -= 1
            if counts[values[lo]] == 0:
                del counts[values[lo]]
            lo += 1
        if len(counts) > best:
            best, best_lo, best_hi = len(counts), lo, hi + 1
    return best, best_lo, best_hi


def max_count_window(times: NDArray[np.float64], window_s: float) -> tuple[int, int, int]:
    """Window with the most events: (count, lo, hi), earliest on ties."""
    best, best_lo, best_hi = 0, 0, 0
    lo = 0
    for hi in range(len(times)):
        while times[hi] - times[lo] > window_s:
            lo += 1
        if hi - lo + 1 > best:
            best, best_lo, best_hi = hi - lo + 1, lo, hi + 1
    return best, best_lo, best_hi
