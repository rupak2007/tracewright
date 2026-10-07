"""Detector evaluation harness v1 (eval/PROTOCOL.md §3, §5, §6; plan P3).

    python -m eval.run_detectors --split dev [--analysis-dir data/analysis] [--run-id ID]

For every run the split manifest assigns to the chosen split, run the five detectors on the run's
P1-analysed tables (`<analysis-dir>/<run_id>/`, produced by `python -m lab.record_corpus` or
`python -m app.cli analyze`) and match findings to the run's verified labels. Writes
`eval/results/<run_id>/manifest.json` and `detectors.json`.

Guard rails enforced here:
  * `--split test` is refused until every P2 corpus requirement is met (`python -m eval.splits
    report`), because the test split is evaluated once per milestone, never for exploration;
  * only runs that pass `lab.verify_run` (eligibility) are read, and the analysis must come from
    the run's own capture (SHA-256 compared to run.json);
  * the detector configuration is read as-is: this tool tunes nothing;
  * with no labelled attack episode in the split, recall and precision are reported as null with the
    reason, never as a number.
Each run is evaluated twice, with and without the network-context allowlists (known scanners and
backup servers, allowlisted domains, periodic ports), so the effect of the allowlists is visible.
"""

import argparse
import json
import subprocess  # fixed argv, shell=False
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.detect.base import DetectorInput
from app.detect.config import DetectorsConfig, load_detectors_config
from app.detect.runner import DetectionReport, run_detectors
from app.ingest.normalise import CaptureTables, read_tables
from app.profile.context import NetworkContext, load_network_context
from eval.matching import FindingView, RunEvaluation, evaluate_run, summarise
from eval.splits import (
    LoadedRun,
    corpus_report,
    load_manifest,
    load_runs,
)

REPO = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO / "eval" / "results"
DEFAULT_ANALYSIS_DIR = REPO / "data" / "analysis"
MODES = ("with_allowlists", "without_allowlists")


class HarnessError(Exception):
    """A precondition failed; nothing is written."""


def without_allowlists(ctx: NetworkContext) -> NetworkContext:
    """Same internal/external classification, no scanners/backup servers/allowlists."""
    return NetworkContext(internal_cidrs=ctx.internal_cidrs)


def check_split_allowed(split: str, manifest: dict[str, Any], runs: dict[str, LoadedRun]) -> None:
    if split not in ("dev", "test"):
        raise HarnessError(f"unknown split {split!r}")
    if split == "test":
        unmet = [r for r in corpus_report(manifest, runs) if not r.met]
        if unmet:
            raise HarnessError(
                f"refusing to evaluate the test split: {len(unmet)} corpus requirement(s) are "
                "unmet (python -m eval.splits report). The test split is evaluated once per "
                "milestone, after the corpus is complete (eval/PROTOCOL.md §5)."
            )


def view(report: DetectionReport) -> list[FindingView]:
    return [
        FindingView(
            f.id,
            f.type,
            f.primary_entity,
            tuple(f.secondary_entities),
            f.start_ts,
            f.end_ts,
            f.confidence,
        )
        for f in report.findings
    ]


def git_state() -> dict[str, Any]:
    def run(*argv: str) -> str:
        done = subprocess.run(  # noqa: S603
            ["git", *argv],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            cwd=REPO,
        )
        return done.stdout.strip()

    return {"commit": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain"))}


def load_analysis(
    run_id: str, loaded: LoadedRun, analysis_dir: Path
) -> tuple[CaptureTables, dict[str, Any], dict[str, Any]]:
    """Tables, status and profile of a run's P1 analysis, checked to be of the run's own capture."""
    root = analysis_dir / run_id
    status_path, profile_path = root / "status.json", root / "profile.json"
    if not (root / "tables").is_dir() or not status_path.exists() or not profile_path.exists():
        raise HarnessError(
            f"no P1 analysis for {run_id} under {analysis_dir} "
            f"(expected tables/, status.json, profile.json); analyse the capture first"
        )
    status = json.loads(status_path.read_text(encoding="utf-8"))
    if status.get("status") != "completed" or status.get("sha256") != loaded.meta.capture_sha256:
        raise HarnessError(
            f"the analysis in {root} is not a completed analysis of {run_id}'s capture"
        )
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    return read_tables(root / "tables"), status, profile


def analyse_run(
    run_id: str,
    loaded: LoadedRun,
    analysis_dir: Path,
    config: DetectorsConfig,
    config_dir: Path,
) -> tuple[dict[str, DetectionReport], dict[str, Any]]:
    tables, status, profile = load_analysis(run_id, loaded, analysis_dir)
    duration = profile["capture"]["duration_s"]
    context = load_network_context(config_dir / loaded.meta.network_config)
    reports = {
        "with_allowlists": run_detectors(
            DetectorInput(tables, context, config, duration), investigation_id=run_id
        ),
        "without_allowlists": run_detectors(
            DetectorInput(tables, without_allowlists(context), config, duration),
            investigation_id=run_id,
        ),
    }
    facts = {
        "capture_sha256": loaded.meta.capture_sha256,
        "zeek_version": status.get("zeek_version"),
        "capture_duration_s": duration,
        "network_config": loaded.meta.network_config,
        "episodes": len(loaded.episodes),
    }
    return reports, facts


def evaluate_split(
    split: str,
    analysis_dir: Path,
    config_path: Path,
    config_dir: Path,
    manifest: dict[str, Any] | None = None,
    runs: dict[str, LoadedRun] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = manifest if manifest is not None else load_manifest()
    runs = runs if runs is not None else load_runs()
    check_split_allowed(split, manifest, runs)
    config = load_detectors_config(config_path)
    selected = sorted(r for r, v in manifest["assigned"].items() if v["split"] == split)
    if not selected:
        raise HarnessError(f"no runs are assigned to the {split} split")
    totals = {mode: RunEvaluation() for mode in MODES}
    hours = 0.0
    per_run: dict[str, Any] = {}
    run_facts: dict[str, Any] = {}
    false_positives: dict[str, list[dict[str, Any]]] = {mode: [] for mode in MODES}
    suppressed_totals: dict[str, dict[str, int]] = {}
    for run_id in selected:
        loaded = runs[run_id]
        reports, facts = analyse_run(run_id, loaded, analysis_dir, config, config_dir)
        run_facts[run_id] = facts
        if loaded.meta.benign_only:
            hours += facts["capture_duration_s"] / 3600.0
        per_run[run_id] = {}
        for mode, report in reports.items():
            evaluation = evaluate_run(view(report), loaded.episodes)
            totals[mode].merge(evaluation)
            per_run[run_id][mode] = {
                "findings_by_type": report.counts_by_type(),
                "suppressed": report.suppressed,
            }
            for finding in report.findings:
                if any(fp[0] == finding.id for fp in evaluation.false_positives):
                    false_positives[mode].append(
                        {
                            "run": run_id,
                            "id": finding.id,
                            "type": finding.type,
                            "confidence": finding.confidence,
                            "primary": finding.primary_entity,
                            "secondary": finding.secondary_entities,
                            "score_or_metrics": {
                                k: finding.metrics[k]
                                for k in (
                                    "series",
                                    "dst_port",
                                    "events",
                                    "beacon_score",
                                    "scan_type",
                                    "service",
                                    "unique_subdomains",
                                    "outbound_bytes",
                                )
                                if k in finding.metrics
                            },
                            "matches_hard_negative": next(
                                (fp[3] for fp in evaluation.false_positives if fp[0] == finding.id),
                                None,
                            ),
                        }
                    )
            if mode == "with_allowlists":
                for det, reasons in report.suppressed.items():
                    bucket = suppressed_totals.setdefault(det, {})
                    for reason, n in reasons.items():
                        bucket[reason] = bucket.get(reason, 0) + n
    attack_total = sum(totals["with_allowlists"].attack_episodes.values())
    metrics: dict[str, Any] = {
        "scope": (
            f"{split} split. Benign lab runs with hard-negative traffic only unless attack "
            "episodes are listed; this is NOT detector performance on attacks."
        ),
        "split": split,
        "runs": selected,
        "benign_hours": round(hours, 4),
        "attack_metrics": (
            "computed"
            if attack_total
            else "not measurable: no labelled attack episode exists in this split"
        ),
        "modes": {mode: summarise(totals[mode], hours) for mode in MODES},
        "false_positive_findings": false_positives,
        "per_run": per_run,
        "suppressed_with_allowlists": suppressed_totals,
    }
    manifest_out = {
        "git": git_state(),
        "config_hash": config.config_hash(),
        "detector_config": str(config_path.relative_to(REPO))
        if config_path.is_relative_to(REPO)
        else str(config_path),
        "split": split,
        "split_seed": manifest.get("seed"),
        "runs": run_facts,
        "timestamp_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return metrics, manifest_out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the detectors on one split.")
    parser.add_argument("--split", required=True, choices=("dev", "test"))
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR)
    parser.add_argument("--config", type=Path, default=REPO / "config" / "detectors.yaml")
    parser.add_argument("--config-dir", type=Path, default=REPO / "config")
    parser.add_argument("--run-id", help="result directory name (default derived from the inputs)")
    parser.add_argument("--out", type=Path, default=RESULTS_DIR)
    args = parser.parse_args(argv)
    try:
        metrics, manifest = evaluate_split(
            args.split, args.analysis_dir, args.config, args.config_dir
        )
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    run_id = args.run_id or f"{args.split}-detectors-{manifest['config_hash'][:8]}"
    target = args.out / run_id
    if target.exists():
        print(f"error: {target} already exists; results are never overwritten", file=sys.stderr)
        return 2
    target.mkdir(parents=True)
    (target / "detectors.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {target}")
    for mode, summary in metrics["modes"].items():
        print(
            f"  {mode}: {summary['findings']} findings, "
            f"{summary['false_positive_findings_medium_high']} medium/high false positives, "
            f"{summary['false_positives_per_benign_hour_medium_high']} per benign hour"
        )
    print(f"  attack metrics: {metrics['attack_metrics']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
