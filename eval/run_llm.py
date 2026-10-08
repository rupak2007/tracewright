"""Generate narratives for a split's incidents and write the blinded audit sheets (gate G2).

    python -m eval.run_llm --split dev|test --run-id ID [--limit N] [--seed 7]
                           [--analysis-dir data/analysis]

The provider comes from the same `LLM_*` environment variables the API reads; with
`LLM_PROVIDER=none` there is nothing to evaluate and the command refuses. `--split test` is refused
until every P2 corpus requirement is met (eval/PROTOCOL.md §5). On `dev` the run only checks the
pipeline and the validator; it is not a G2 evaluation (the gate is decided on test incidents).

Outputs (never overwritten):
  eval/results/<run_id>/llm_narratives.json   one record per incident: pack, template, status,
                                              attempts, reasons, output, raw model text
  eval/results/<run_id>/manifest.json         provider, model, prompt hash, git state, seed
  eval/audit/<run_id>/                        statements-TEMPLATE.csv, pairs-TEMPLATE.csv for raters
                                              and answer_key.json (kept from the raters)
Raters copy the templates to statements-<rater>.csv / pairs-<rater>.csv and fill the last columns;
`python -m eval.score_llm` pools the completed files.
"""

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import PipelineSettings, get_llm_settings
from app.correlate.runner import correlate
from app.detect.base import DetectorInput
from app.detect.runner import run_detectors
from app.explain.evidence_pack import build_pack
from app.explain.llm_client import LlmClient, LlmUnavailable, make_client
from app.explain.narrative import generate_narrative, prompt_hash
from app.explain.pseudonymise import Pseudonymiser
from app.profile.context import load_network_context
from app.report.assemble import assemble_analysis
from app.worker.analysis_config import AnalysisConfig, load_analysis_config
from eval.llm_eval import build_sheets, write_sheets
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

AUDIT_DIR = REPO / "eval" / "audit"


def records_for_run(
    run_id: str,
    loaded: LoadedRun,
    analysis_dir: Path,
    acfg: AnalysisConfig,
    client: LlmClient,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Run the product's own detect/correlate/explain stages on a run's tables, then generate and
    validate one narrative per incident (the same code path the API uses)."""
    tables, _status, profile = load_analysis(run_id, loaded, analysis_dir)
    capture = profile["capture"]
    network = load_network_context(acfg.config_dir / loaded.meta.network_config)
    report = run_detectors(
        DetectorInput(tables, network, acfg.detectors, capture["duration_s"]), run_id
    )
    correlation = correlate(report.findings, acfg.correlation)
    analysis = assemble_analysis(
        investigation_id=run_id,
        capture_sha256=loaded.meta.capture_sha256,
        report=report,
        correlation=correlation,
        tables=tables,
        mapping=acfg.mapping,
        cards=acfg.cards,
        playbooks=acfg.playbooks,
    )
    records: list[dict[str, Any]] = []
    for detail in analysis.incidents[: limit if limit is not None else None]:
        pack = build_pack(
            detail,
            capture_start=float(capture.get("first_ts") or detail.incident.start_ts.timestamp()),
            capture_span_s=capture.get("duration_s"),
            warning_codes=[
                str(w.get("code")) for w in profile.get("warnings", []) if isinstance(w, dict)
            ],
            max_beacon_interval_s=profile.get("max_beacon_interval_s"),
            pseudo=Pseudonymiser(lambda ip: network.classify(ip) == "internal"),
            cards=acfg.cards,
            playbooks=acfg.playbooks,
        )
        result = generate_narrative(pack, client)
        records.append(
            {
                "run_id": run_id,
                "incident": detail.incident.id,
                "pack": pack.pack,
                "template": detail.summary,
                "status": result.status,
                "attempts": result.attempts,
                "reasons": result.reasons,
                "output": result.output.model_dump() if result.output else None,
                "raw_output": result.raw_output,
            }
        )
    return records


def generate_split(
    split: str,
    analysis_dir: Path,
    client: LlmClient,
    seed: int,
    limit: int | None = None,
    manifest: dict[str, Any] | None = None,
    runs: dict[str, LoadedRun] | None = None,
    analysis_config: AnalysisConfig | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest = manifest if manifest is not None else load_manifest()
    runs = runs if runs is not None else load_runs()
    check_split_allowed(split, manifest, runs)
    selected = sorted(r for r, v in manifest["assigned"].items() if v["split"] == split)
    if not selected:
        raise HarnessError(f"no runs are assigned to the {split} split")
    acfg = analysis_config or load_analysis_config(
        PipelineSettings(config_dir=REPO / "config", knowledge_dir=REPO / "knowledge")
    )
    records: list[dict[str, Any]] = []
    for run_id in selected:
        remaining = None if limit is None else limit - len(records)
        if remaining is not None and remaining <= 0:
            break
        records += records_for_run(run_id, runs[run_id], analysis_dir, acfg, client, remaining)
    run_manifest = {
        "split": split,
        "runs": selected,
        "provider": client.provider,
        "model": client.model,
        "temperature": 0,
        "prompt_hash": prompt_hash(),
        "seed": seed,
        "incidents": len(records),
        "generated_at": datetime.now(UTC).isoformat(),
        "git": git_state(),
        "purpose": "g2_evaluation" if split == "test" else "pipeline_check_not_a_g2_evaluation",
    }
    return records, run_manifest


def write_outputs(
    records: Sequence[dict[str, Any]],
    run_manifest: dict[str, Any],
    run_id: str,
    out: Path,
    audit: Path,
) -> Path:
    target = out / run_id
    if target.exists() or (audit / run_id).exists():
        raise HarnessError(f"{run_id} already exists; results and sheets are never overwritten")
    target.mkdir(parents=True)
    (target / "llm_narratives.json").write_text(
        json.dumps({"records": list(records)}, indent=2) + "\n", encoding="utf-8"
    )
    (target / "manifest.json").write_text(json.dumps(run_manifest, indent=2) + "\n", "utf-8")
    statements, pairs, key = build_sheets(records, int(run_manifest["seed"]))
    write_sheets(audit / run_id, statements, pairs, key)
    return target


def main(
    argv: Sequence[str] | None = None,
    client_factory: Callable[[], LlmClient] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else "")
    parser.add_argument("--split", required=True, choices=("dev", "test"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR)
    parser.add_argument("--audit-dir", type=Path, default=AUDIT_DIR)
    args = parser.parse_args(argv)
    try:
        client = client_factory() if client_factory else make_client(get_llm_settings())
        if client.provider == "none":
            raise HarnessError("LLM_PROVIDER is none: there is no model to evaluate")
        records, manifest = generate_split(
            args.split, args.analysis_dir, client, args.seed, args.limit
        )
        target = write_outputs(records, manifest, args.run_id, args.out, args.audit_dir)
    except (HarnessError, LlmUnavailable) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    by_status: dict[str, int] = {}
    for r in records:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    print(f"wrote {target} ({len(records)} incidents: {by_status})")
    print(f"audit sheets: {args.audit_dir / args.run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
