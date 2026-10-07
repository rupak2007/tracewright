"""Anomaly experiment (plan P5, gate G1; eval/PROTOCOL.md §5-7).

    python -m eval.run_anomaly calibrate [--analysis-dir data/analysis] [--run-id ID]
    python -m eval.run_anomaly evaluate --split dev|test [--analysis-dir ...] [--run-id ID]

calibrate  scores the BENIGN runs of the `dev` split and picks, per scorer, the promotion cut-off
           such that at most 1% of the pooled rule-unexplained benign windows reach it. Only reads
           dev runs (asserted), writes eval/results/<run_id>/anomaly_calibration.json and prints the
           values to put in config/anomaly.yaml (an entry in eval/REVISIONS.md is still required).
           The per-capture minimum-population rule is waived here: calibration needs the scores
           themselves, even for captures too small for the product to run the stage.
evaluate   computes, for `robust_z`, `iforest` and the random baseline, precision@10, recall@10,
           PR-AUC per capture on the split's LAB-HOLDOUT runs, the benign promoted rate on its
           benign runs, the capture-level bootstrap of the precision@10 difference, and the G1 rule.
           `--split test` is refused until every P2 corpus requirement is met; with no LAB-HOLDOUT
           run in the split nothing is computed and the report says "not measurable".
Nothing here tunes on `test`, and the result files carry the manifest the protocol requires.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from app.anomaly.config import AnomalyConfig, load_anomaly_config
from app.anomaly.triage import TriageResult, triage
from app.detect.base import DetectorInput
from app.detect.config import load_detectors_config
from app.detect.runner import run_detectors
from app.profile.context import load_network_context
from eval.anomaly_metrics import (
    WindowRef,
    bootstrap_difference,
    decide_g1,
    pr_auc,
    precision_at_k,
    promoted_rate,
    recall_at_k,
)
from eval.run_detectors import (
    DEFAULT_ANALYSIS_DIR,
    REPO,
    RESULTS_DIR,
    HarnessError,
    check_split_allowed,
    git_state,
    load_analysis,
)
from eval.splits import LoadedRun, load_manifest, load_runs

SCORERS = ("robust_z", "iforest")
BENIGN_QUANTILE_LIMIT = 0.01


def calibrated_threshold(
    scores: Sequence[float], limit: float = BENIGN_QUANTILE_LIMIT
) -> float | None:
    """Smallest cut-off with at most `limit` of `scores` at or above it (None for no scores).

    With k = floor(limit * n) allowed exceedances, the cut-off is the next representable value above
    the (k+1)-th largest score, so ties can never push the exceedance count over k."""
    if not scores:
        return None
    ordered = sorted(scores, reverse=True)
    allowed = int(limit * len(ordered))
    pivot = ordered[min(allowed, len(ordered) - 1)]
    return float(np.nextafter(pivot, np.inf))


def _scored_run(
    run_id: str, loaded: LoadedRun, analysis_dir: Path, cfg: AnomalyConfig, scorer: str
) -> tuple[TriageResult, dict[str, Any]]:
    tables, status, profile = load_analysis(run_id, loaded, analysis_dir)
    network = load_network_context(REPO / "config" / loaded.meta.network_config)
    det_cfg = load_detectors_config(REPO / "config" / "detectors.yaml")
    findings = run_detectors(
        DetectorInput(tables, network, det_cfg, profile["capture"]["duration_s"]), run_id
    ).findings
    result = triage(tables, network, findings, cfg, scorer, skip_population_check=True)
    return result, {
        "capture_sha256": loaded.meta.capture_sha256,
        "zeek_version": status.get("zeek_version"),
        "windows": result.windows,
        "rule_unexplained": result.unexplained,
    }


def _refs(result: TriageResult, window_s: float) -> list[WindowRef]:
    if result.scores.empty:
        return []
    return [
        WindowRef(str(h), float(s), float(s) + window_s, float(sc), bool(ex))
        for h, s, sc, ex in zip(
            result.scores["host"].tolist(),
            result.scores["window_start"].tolist(),
            result.scores["score"].tolist(),
            result.scores["rule_explained"].tolist(),
            strict=True,
        )
    ]


def calibrate(
    analysis_dir: Path, cfg: AnomalyConfig, manifest: dict[str, Any], runs: dict[str, LoadedRun]
) -> dict[str, Any]:
    dev = sorted(r for r, v in manifest["assigned"].items() if v["split"] == "dev")
    benign = [r for r in dev if runs[r].meta.benign_only]
    if not benign:
        raise HarnessError("no benign run is assigned to the dev split")
    pooled: dict[str, list[float]] = {s: [] for s in SCORERS}
    facts: dict[str, Any] = {}
    for run_id in benign:
        for scorer in SCORERS:
            result, info = _scored_run(run_id, runs[run_id], analysis_dir, cfg, scorer)
            facts[run_id] = info
            if not result.scores.empty:
                unexplained = result.scores[~result.scores["rule_explained"]]
                pooled[scorer] += [float(v) for v in unexplained["score"]]
    thresholds = {s: calibrated_threshold(v) for s, v in pooled.items()}
    return {
        "scope": "BENIGN dev runs only; cut-off keeps at most 1% of pooled unexplained windows",
        "runs": benign,
        "pooled_windows": {s: len(v) for s, v in pooled.items()},
        "promotion_threshold": thresholds,
        "benign_promoted_rate_at_threshold": {
            s: promoted_rate(pooled[s], thresholds[s]) for s in SCORERS
        },
        "window_s": cfg.window_s,
        "per_run": facts,
        "caveat": "few windows (small lab population): the cut-off rests on very few observations",
    }


def evaluate(
    split: str,
    analysis_dir: Path,
    cfg: AnomalyConfig,
    manifest: dict[str, Any],
    runs: dict[str, LoadedRun],
) -> dict[str, Any]:
    check_split_allowed(split, manifest, runs)
    selected = sorted(r for r, v in manifest["assigned"].items() if v["split"] == split)
    holdout = [r for r in selected if runs[r].meta.holdout]
    benign = [r for r in selected if runs[r].meta.benign_only]
    per_scorer: dict[str, Any] = {}
    benign_scores: dict[str, list[float]] = {s: [] for s in (*SCORERS, "random")}
    captures: dict[str, dict[str, list[float | None]]] = {
        s: {"p10": [], "r10": [], "ap": []} for s in (*SCORERS, "random")
    }
    for scorer in (*SCORERS, "random"):
        for run_id in benign:
            result, _ = _scored_run(run_id, runs[run_id], analysis_dir, cfg, scorer)
            if not result.scores.empty:
                benign_scores[scorer] += [
                    float(v) for v in result.scores[~result.scores["rule_explained"]]["score"]
                ]
        for run_id in holdout:
            result, _ = _scored_run(run_id, runs[run_id], analysis_dir, cfg, scorer)
            refs = _refs(result, cfg.window_s)
            episodes = [e for e in runs[run_id].episodes if e.kind == "holdout"]
            captures[scorer]["p10"].append(precision_at_k(refs, episodes))
            captures[scorer]["r10"].append(recall_at_k(refs, episodes))
            captures[scorer]["ap"].append(pr_auc(refs, episodes))

    def mean(values: list[float | None]) -> float | None:
        usable = [v for v in values if v is not None]
        return float(np.mean(usable)) if usable else None

    for scorer in (*SCORERS, "random"):
        c = captures[scorer]
        per_scorer[scorer] = {
            "precision_at_10": mean(c["p10"]),
            "recall_at_10": mean(c["r10"]),
            "pr_auc": mean(c["ap"]),
            "benign_promoted_rate": promoted_rate(benign_scores[scorer], cfg.threshold_for(scorer)),
        }
    paired = [
        (a, b)
        for a, b in zip(captures["iforest"]["p10"], captures["robust_z"]["p10"], strict=True)
        if a is not None and b is not None
    ]
    ci = bootstrap_difference([a for a, _ in paired], [b for _, b in paired]) if paired else None
    measurable = bool(holdout)
    decision, reason = decide_g1(
        per_scorer["iforest"]["precision_at_10"],
        per_scorer["robust_z"]["precision_at_10"],
        ci,
        per_scorer["iforest"]["benign_promoted_rate"],
        per_scorer["robust_z"]["recall_at_10"],
        per_scorer["robust_z"]["benign_promoted_rate"],
    )
    return {
        "scope": f"{split} split; held-out metrics need LAB-HOLDOUT runs",
        "split": split,
        "holdout_runs": holdout,
        "benign_runs": benign,
        "holdout_metrics": "computed"
        if measurable
        else "not measurable: no LAB-HOLDOUT run in this split",
        "scorers": per_scorer,
        "precision_at_10_difference_iforest_minus_robust_z": (
            None if ci is None else {"mean": ci[0], "ci95": [ci[1], ci[2]]}
        ),
        "g1_decision": decision if measurable else "not decided",
        "g1_reason": reason if measurable else "G1 cannot be decided without held-out captures",
    }


def _write(out: Path, run_id: str, name: str, payload: dict[str, Any], cfg_path: Path) -> Path:
    target = out / run_id
    if target.exists():
        raise HarnessError(f"{target} already exists; results are never overwritten")
    target.mkdir(parents=True)
    (target / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "git": git_state(),
        "anomaly_config": cfg_path.name,
        "timestamp_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "runs": payload.get("runs") or payload.get("benign_runs"),
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return target


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Anomaly calibration and G1 evaluation.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("calibrate", "evaluate"):
        p = sub.add_parser(name)
        p.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR)
        p.add_argument("--config", type=Path, default=REPO / "config" / "anomaly.yaml")
        p.add_argument("--run-id")
        p.add_argument("--out", type=Path, default=RESULTS_DIR)
        if name == "evaluate":
            p.add_argument("--split", required=True, choices=("dev", "test"))
    args = parser.parse_args(argv)
    cfg = load_anomaly_config(args.config)
    manifest, runs = load_manifest(), load_runs()
    try:
        if args.command == "calibrate":
            payload = calibrate(args.analysis_dir, cfg, manifest, runs)
            target = _write(
                args.out,
                args.run_id or "anomaly-calibration-dev",
                "anomaly_calibration.json",
                payload,
                args.config,
            )
            print(f"wrote {target}")
            for scorer, value in payload["promotion_threshold"].items():
                print(f"  {scorer}: promotion_threshold = {value}")
        else:
            payload = evaluate(args.split, args.analysis_dir, cfg, manifest, runs)
            target = _write(
                args.out,
                args.run_id or f"anomaly-{args.split}",
                "anomaly.json",
                payload,
                args.config,
            )
            print(f"wrote {target}\n  G1: {payload['g1_decision']} ({payload['g1_reason']})")
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
