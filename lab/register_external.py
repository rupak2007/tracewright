"""Register a capture that was produced OUTSIDE the lab runner.

    python -m lab.register_external <submission_dir> [--runs-dir lab/runs] [--data-dir data/lab]

<submission_dir> must contain exactly:
    submission.json     declaration of the run (see lab/submission.py for every required field)
    labels.jsonl        ground-truth episodes (schema: lab/schema.py)
    capture.pcap | capture.pcapng

This command does not generate traffic and does not decide that anything is valid. It checks the
paperwork and the file, then stages the run as *unverified*:
  1. submission.json and labels.jsonl parse, are complete, and agree with each other;
  2. the capture passes P1 file validation (magic bytes, size, no compression) and its SHA-256 is
     computed here (a supplier-stated hash is not accepted);
  3. the run id and the capture hash are new (no duplicate runs, no capture reused under a new id);
  4. only then are run.json + labels.jsonl written to <runs-dir>/<run_id>/ and the capture copied
     to <data-dir>/<run_id>/ (gitignored).
A staged run is NOT eligible for any split until `lab.verify_run` passes. Needs the backend env.
Exit status: 0 staged, 1 rejected, 2 unreadable input.
"""

import argparse
import json
import shutil
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from app.core.errors import IngestError
from app.ingest.validate import validate_file
from lab.labeler import read_labels
from lab.runmeta import RunMeta, load_run
from lab.schema import parse_time
from lab.submission import (
    Submission,
    check_labels_match_submission,
    check_run_flags,
    parse_submission,
)

REPO = Path(__file__).resolve().parents[1]
MAX_CAPTURE_BYTES = 8 * 1024**3
CAPTURE_NAMES = ("capture.pcap", "capture.pcapng")


class RegistrationError(ValueError):
    """The submission was rejected; nothing was written."""


def _existing_runs(runs_dir: Path) -> dict[str, RunMeta]:
    runs: dict[str, RunMeta] = {}
    if runs_dir.exists():
        for run_dir in sorted(
            p for p in runs_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
        ):
            if (run_dir / "run.json").exists():
                runs[run_dir.name] = load_run(run_dir / "run.json")
    return runs


def register(
    source: Path,
    runs_dir: Path,
    data_dir: Path,
    config_dir: Path,
    max_capture_bytes: int = MAX_CAPTURE_BYTES,
) -> RunMeta:
    """Validate a submission directory and stage it. Raises RegistrationError on any problem."""
    try:
        submission: Submission = parse_submission(
            json.loads((source / "submission.json").read_text(encoding="utf-8"))
        )
    except (OSError, ValueError) as exc:
        raise RegistrationError(f"submission.json: {exc}") from exc
    try:
        episodes = read_labels(source / "labels.jsonl")
    except (OSError, ValueError) as exc:
        raise RegistrationError(f"labels.jsonl: {exc}") from exc

    problems = check_labels_match_submission(submission, episodes)
    if not (config_dir / submission.network_config).is_file():
        problems.append(f"network_config {submission.network_config!r} not found in config/")
    benign_only = all(e.kind == "hard_negative" for e in episodes)
    problems += check_run_flags(submission.holdout, benign_only, list(episodes))

    captures = [source / name for name in CAPTURE_NAMES if (source / name).is_file()]
    if len(captures) != 1:
        problems.append("expected exactly one of capture.pcap / capture.pcapng")
    existing = _existing_runs(runs_dir)
    if submission.run_id in existing or (runs_dir / submission.run_id).exists():
        problems.append(f"run_id {submission.run_id!r} is already registered")
    if (data_dir / submission.run_id).exists():
        problems.append(f"{data_dir / submission.run_id} already exists")
    if problems:
        raise RegistrationError("; ".join(problems))

    capture = captures[0]
    try:
        info = validate_file(capture, max_capture_bytes)
    except IngestError as exc:
        raise RegistrationError(f"capture rejected: {exc.code}: {exc.message}") from exc
    for other_id, other in existing.items():
        if other.capture_sha256 == info.sha256:
            raise RegistrationError(
                f"this capture is already registered as run {other_id!r}; reusing a capture "
                "under a new run id would leak it across splits"
            )

    window = parse_time(submission.end) - parse_time(submission.start)
    meta = RunMeta(
        run_id=submission.run_id,
        capture_sha256=info.sha256,
        capture_bytes=info.size_bytes,
        start=submission.start,
        end=submission.end,
        seed=None,
        holdout=submission.holdout,
        benign_only=benign_only,
        duration_s=round(window / timedelta(seconds=1), 3),
        scenarios=tuple(
            {"kind": s.kind, "class": s.cls, "client": s.client, "tool": s.tool}
            for s in submission.scenarios
        ),
        network_config=submission.network_config,
        origin="external",
        clients=submission.clients,
        provenance={
            "supplied_by": submission.provenance.supplied_by,
            "supplied_at": submission.provenance.supplied_at,
            "collection_method": submission.provenance.collection_method,
            "tool_versions": submission.provenance.tool_versions,
            "isolated_environment": submission.provenance.isolated_environment,
            "contains_real_user_data": submission.provenance.contains_real_user_data,
            "scenario_parameters": submission.provenance.scenario_parameters,
            "notes": submission.provenance.notes,
        },
    )

    staging = runs_dir / f".staging-{submission.run_id}"
    capture_dir = data_dir / submission.run_id
    try:
        staging.mkdir(parents=True)
        (staging / "run.json").write_text(meta.to_json(), encoding="utf-8")
        shutil.copyfile(source / "labels.jsonl", staging / "labels.jsonl")
        capture_dir.mkdir(parents=True)
        shutil.copyfile(capture, capture_dir / f"capture.{info.format.value}")
        staging.rename(runs_dir / submission.run_id)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(capture_dir, ignore_errors=True)
        raise
    return meta


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage an externally supplied run (unverified).")
    parser.add_argument("submission_dir", type=Path)
    parser.add_argument("--runs-dir", type=Path, default=REPO / "lab" / "runs")
    parser.add_argument("--data-dir", type=Path, default=REPO / "data" / "lab")
    parser.add_argument("--config-dir", type=Path, default=REPO / "config")
    args = parser.parse_args(argv)
    try:
        meta = register(args.submission_dir, args.runs_dir, args.data_dir, args.config_dir)
    except RegistrationError as exc:
        print(f"REJECTED  {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"cannot read submission: {exc}", file=sys.stderr)
        return 2
    print(f"staged {meta.run_id} as UNVERIFIED (capture sha256 {meta.capture_sha256})")
    print(
        "next: analyse the capture in the worker, then `python -m lab.verify_run "
        f"{meta.run_id} <analysis_dir>`; the run is not eligible for a split until that passes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
