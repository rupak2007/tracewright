"""Beacon detectability sweep (plan P3, eval/PROTOCOL.md §6): interval x jitter x capture duration.

    python -m eval.beacon_sweep [--run-id ID] [--out eval/results]

SYNTHETIC TIMING MODEL, not detection performance. No capture is read. For every cell, a perfectly
size-regular series of check-ins is generated (interval I with uniform jitter of +-J*I, starting at
t = 0, ending at the capture duration D) and scored with the same `beacon_scores` the detector
uses; a cell's rate is the share of seeds whose series would fire the rule (>= min_events events and
score >= min_score). It shows where the scoring rule can and cannot fire as a function of timing
alone: the detectability limit D >= 10 x I from PRD §10, and how jitter and partial capture
coverage erode the score. Real beacons add size variation, missed beats and background traffic,
and real detection rates are NOT inferred from this table.
"""

import argparse
import json
import random
import subprocess  # fixed argv, shell=False
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from app.detect.beacon import beacon_scores
from app.detect.config import BeaconConfig, load_detectors_config

REPO = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO / "eval" / "results"
INTERVALS_S = (10, 30, 60, 300, 900)
JITTERS = (0.0, 0.1, 0.25, 0.5)
DURATIONS_S = (600, 1800, 3600, 7200, 14400)
SEEDS = 20


def series(interval_s: float, jitter: float, duration_s: float, seed: int) -> list[float]:
    rng = random.Random(f"{interval_s}-{jitter}-{duration_s}-{seed}")  # noqa: S311  # seeded model
    t, times = 0.0, []
    while t <= duration_s:
        times.append(t)
        t += interval_s * (1 + rng.uniform(-jitter, jitter))
    return times


def cell(interval_s: float, jitter: float, duration_s: float, cfg: BeaconConfig) -> dict[str, Any]:
    fired, scores, events = 0, [], []
    for seed in range(SEEDS):
        times = series(interval_s, jitter, duration_s, seed)
        events.append(len(times))
        if len(times) < cfg.min_events:
            continue
        s = beacon_scores(
            np.array(times, dtype=np.float64),
            np.full(len(times), 512.0),
            float(duration_s),
            cfg,
        )
        scores.append(s.score)
        fired += s.score >= cfg.min_score
    return {
        "interval_s": interval_s,
        "jitter": jitter,
        "capture_duration_s": duration_s,
        "mean_events": round(float(np.mean(events)), 2),
        "seeds": SEEDS,
        "fire_rate": fired / SEEDS,
        "mean_score_when_enough_events": round(float(np.mean(scores)), 4) if scores else None,
    }


def sweep(cfg: BeaconConfig) -> dict[str, Any]:
    cells = [cell(i, j, d, cfg) for i in INTERVALS_S for j in JITTERS for d in DURATIONS_S]
    return {
        "scope": (
            "SYNTHETIC timing model of the beacon score; not detection performance on real "
            "traffic (no capture is read)."
        ),
        "min_events": cfg.min_events,
        "min_score": cfg.min_score,
        "seeds_per_cell": SEEDS,
        "cells": cells,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synthetic beacon detectability sweep.")
    parser.add_argument("--config", type=Path, default=REPO / "config" / "detectors.yaml")
    parser.add_argument("--run-id", default="beacon-sweep-v1")
    parser.add_argument("--out", type=Path, default=RESULTS_DIR)
    args = parser.parse_args(argv)
    config = load_detectors_config(args.config)
    target = args.out / args.run_id
    if target.exists():
        print(f"error: {target} already exists; results are never overwritten", file=sys.stderr)
        return 2
    result = sweep(config.beacon)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        cwd=REPO,
    ).stdout.strip()
    target.mkdir(parents=True)
    (target / "sweep.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (target / "manifest.json").write_text(
        json.dumps(
            {
                "git_commit": commit,
                "config_hash": config.config_hash(),
                "timestamp_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "intervals_s": INTERVALS_S,
                "jitters": JITTERS,
                "durations_s": DURATIONS_S,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
