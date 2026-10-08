"""Score completed G2 audit sheets and apply the pre-declared rule.

    python -m eval.score_llm --run-id ID [--write-decision]

Reads eval/results/<run_id>/llm_narratives.json and every completed `statements-<rater>.csv` /
`pairs-<rater>.csv` in eval/audit/<run_id>/ (the `-TEMPLATE` files are ignored), writes
eval/results/<run_id>/g2.json and prints the decision. With fewer than 30 incidents, fewer than 3
raters or missing ratings the decision is "not_measurable" and `--write-decision` refuses to write
a passed/failed record (eval/decisions/G2.md stays as it is).
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from eval.llm_eval import decide_g2, read_sheet, score
from eval.run_detectors import RESULTS_DIR, HarnessError
from eval.run_llm import AUDIT_DIR

DECISION_PATH = Path(__file__).resolve().parent / "decisions" / "G2.md"
_THRESHOLDS = (
    ("validator pass rate", "validator_pass_rate", ">= 0.90"),
    ("observed-statement support", "observed_support", ">= 0.95"),
    ("unsupported inferences", "unsupported_inferences", "<= 0.05"),
    ("citation correctness", "citation_correctness", ">= 0.90"),
    ("preference over the template", "preference", ">= 0.60"),
)


def load_sheets(audit: Path, prefix: str) -> dict[str, list[dict[str, str]]]:
    sheets = {}
    for path in sorted(audit.glob(f"{prefix}-*.csv")):
        rater = path.stem.removeprefix(f"{prefix}-")
        if rater.upper() != "TEMPLATE":
            sheets[rater] = read_sheet(path)
    return sheets


def decision_markdown(run_id: str, metrics: dict[str, object], decision: str, why: str) -> str:
    rows = "\n".join(
        f"| {label} | {metrics[key]} | {threshold} |" for label, key, threshold in _THRESHOLDS
    )
    default = (
        "`LLM_PROVIDER` may be configured; the narrative stays opt-in per incident"
        if decision == "enabled_by_configuration"
        else "`LLM_PROVIDER=none` (default); templates are the only summary"
    )
    return (
        "# Gate G2 decision (LLM narrative)\n\n"
        f"| Field | Value |\n|---|---|\n| Decision | **{decision}** |\n| Reason | {why} |\n"
        f"| Result files | `eval/results/{run_id}/` and `eval/audit/{run_id}/` |\n"
        f"| Default configuration | {default} |\n\n"
        f"Incidents with a model outcome: {metrics['incidents_with_model_outcome']}; raters: "
        f"{metrics['raters']}.\n\n| Measure | Value | Rule |\n|---|---|---|\n{rows}\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else "")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR)
    parser.add_argument("--audit-dir", type=Path, default=AUDIT_DIR)
    parser.add_argument("--write-decision", action="store_true")
    args = parser.parse_args(argv)
    try:
        results = args.out / args.run_id
        narratives = results / "llm_narratives.json"
        if not narratives.exists():
            raise HarnessError(f"{narratives} does not exist: run eval.run_llm first")
        run_manifest = json.loads((results / "manifest.json").read_text(encoding="utf-8"))
        records = json.loads(narratives.read_text(encoding="utf-8"))["records"]
        audit = args.audit_dir / args.run_id
        key = json.loads((audit / "answer_key.json").read_text(encoding="utf-8"))
        metrics = score(records, load_sheets(audit, "statements"), load_sheets(audit, "pairs"), key)
        decision, why = decide_g2(metrics)
        if args.write_decision and decision == "not_measurable":
            raise HarnessError(f"not measurable ({why}); no decision record is written")
        if args.write_decision and run_manifest.get("split") != "test":
            raise HarnessError("a G2 decision may only be recorded from a test-split run")
    except (HarnessError, OSError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = {"metrics": metrics, "decision": decision, "reason": why, "manifest": run_manifest}
    (results / "g2.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"decision": decision, "reason": why, **metrics}, indent=2))
    if args.write_decision:
        DECISION_PATH.write_text(
            decision_markdown(args.run_id, metrics, decision, why), encoding="utf-8", newline="\n"
        )
        print(f"wrote {DECISION_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
