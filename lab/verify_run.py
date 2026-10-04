"""Verify a registered run against its analysed capture and record the outcome.

    python -m lab.verify_run <run_id> <analysis_dir> [--runs-dir lab/runs] [--tolerance-s 5]

<analysis_dir> is the output of `tracewright analyze` run (in the worker) on the run's capture.
The command checks, without trusting the supplier:
  * the analysis was produced from the SAME capture the run declares (SHA-256 must match);
  * every labelled episode's actor and a target actually talk in the capture inside the labelled
    range (lab.checks), and the declared window lies inside the capture's time span;
  * run-level flags agree with the labelled kinds.
It never edits labels or metadata. It writes `<runs-dir>/<run_id>/verification.json`, `passed`
only when there are no problems. A failed run stays ineligible for any split.
Exit status: 0 passed, 1 failed verification, 2 unreadable input.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

import pandas as pd

from lab.checks import check_run
from lab.labeler import read_labels
from lab.runmeta import load_run
from lab.submission import check_run_flags
from lab.verification import FILE_NAME, Verification, now_stamp, sha256_file

REPO = Path(__file__).resolve().parents[1]


def verify_run(run_dir: Path, analysis_dir: Path, tolerance_s: float = 5.0) -> Verification:
    meta = load_run(run_dir / "run.json")
    labels_path = run_dir / "labels.jsonl"
    episodes = read_labels(labels_path) if labels_path.exists() else []
    conn = pd.read_parquet(analysis_dir / "tables" / "conn.parquet")
    profile = json.loads((analysis_dir / "profile.json").read_text(encoding="utf-8"))
    status = json.loads((analysis_dir / "status.json").read_text(encoding="utf-8"))

    problems: list[str] = []
    if status.get("status") != "completed":
        problems.append(f"analysis did not complete (status {status.get('status')!r})")
    if profile["file"]["sha256"] != meta.capture_sha256:
        problems.append("analysis was run on a different capture than the one this run declares")
    if meta.run_id != run_dir.name:
        problems.append(f"run.json run_id {meta.run_id!r} != directory {run_dir.name!r}")
    problems += check_run_flags(meta.holdout, meta.benign_only, list(episodes))
    capture = profile["capture"]
    problems += check_run(
        episodes, meta.run_id, conn, capture["first_ts"], capture["last_ts"], tolerance_s
    )
    if not episodes and not meta.benign_only:
        problems.append("no labelled episodes")
    return Verification(
        run_id=meta.run_id,
        passed=not problems,
        problems=tuple(problems),
        capture_sha256=meta.capture_sha256,
        run_json_sha256=sha256_file(run_dir / "run.json"),
        labels_sha256=sha256_file(labels_path),
        analysis_zeek_version=str(profile.get("zeek_version", "")),
        analysis_connections=len(conn),
        verified_at=now_stamp(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a registered run against its analysis.")
    parser.add_argument("run_id")
    parser.add_argument("analysis_dir", type=Path)
    parser.add_argument("--runs-dir", type=Path, default=REPO / "lab" / "runs")
    parser.add_argument("--tolerance-s", type=float, default=5.0)
    args = parser.parse_args(argv)
    run_dir = args.runs_dir / args.run_id
    try:
        result = verify_run(run_dir, args.analysis_dir, args.tolerance_s)
    except (OSError, ValueError, KeyError) as exc:
        print(f"cannot verify: {exc}", file=sys.stderr)
        return 2
    (run_dir / FILE_NAME).write_text(result.to_json(), encoding="utf-8")
    for problem in result.problems:
        print(f"PROBLEM  {problem}")
    print(f"{args.run_id}: {'PASSED' if result.passed else 'FAILED'} ({FILE_NAME} written)")
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
