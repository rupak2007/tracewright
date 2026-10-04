"""Verify a run's labels against its analysed capture.

    python -m lab.check_labels <run_dir> <analysis_dir> [--tolerance-s 5]   (from the repo root)

<run_dir>       contains labels.jsonl (and run.json)
<analysis_dir>  output of `tracewright analyze` for the run's capture (tables/conn.parquet,
                profile.json). Needs the backend environment (pandas, pyarrow).
Exit status: 0 consistent, 1 problems found, 2 unreadable input.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

import pandas as pd

from lab.checks import check_run
from lab.labeler import read_labels


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("analysis_dir", type=Path)
    parser.add_argument("--tolerance-s", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        episodes = read_labels(args.run_dir / "labels.jsonl")
        conn = pd.read_parquet(args.analysis_dir / "tables" / "conn.parquet")
        profile = json.loads((args.analysis_dir / "profile.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"cannot read inputs: {exc}", file=sys.stderr)
        return 2
    capture = profile["capture"]
    problems = check_run(
        episodes,
        args.run_dir.name,
        conn,
        capture["first_ts"],
        capture["last_ts"],
        args.tolerance_s,
    )
    print(f"{len(episodes)} episode(s) checked against {len(conn)} connection(s)")
    for problem in problems:
        print(f"PROBLEM  {problem}")
    if not episodes:
        print("PROBLEM  no episodes in labels.jsonl (a run without labels is not ground truth)")
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
