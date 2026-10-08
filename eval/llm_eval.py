"""Gate G2 mechanics (PRD §12, eval/PROTOCOL.md §8): audit sheets, scoring and the decision rule.

Pure functions only; `eval.run_llm` generates the narratives and `eval.score_llm` reads completed
sheets. Nothing here calls a model.

G2 (verbatim, PRD §12): the narrative feature ships enabled-by-configuration only if, on the
evaluation set: validator pass rate >= 90% (<= 1 repair attempt); manual audit shows
observed-statement support >= 95%, unsupported inferences <= 5%, citation correctness >= 90%; and
raters prefer it over the template in >= 60% of blind pairwise comparisons. Otherwise templates
remain the only summary and the result is documented.

Interpretations the PRD leaves open, fixed here before any rating exists:
* validator pass rate = validated / (validated + rejected); an `unavailable` incident (the
  provider failed) is not a model outcome and makes the run not measurable if any occur;
* sheets from several raters are pooled (each completed file is one rater);
* preference = narrative preferred / ALL rated pairs, ties count as not preferred (conservative);
* the evaluation set needs >= 30 incidents with a model outcome, >= 3 raters (plan P8) and rated
  statements and pairs; below that the gate is "not measurable", never "passed" or "failed".
"""

import csv
import json
import random
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

MIN_INCIDENTS = 30
MIN_RATERS = 3
PASS_RATE_MIN = 0.90
OBSERVED_SUPPORT_MIN = 0.95
UNSUPPORTED_INFERENCE_MAX = 0.05
CITATION_CORRECT_MIN = 0.90
PREFERENCE_MIN = 0.60

STATEMENT_COLUMNS = [
    "item_id",
    "incident",
    "kind",
    "text",
    "cited",
    "cited_evidence",
    "supported",
    "citation_correct",
]
PAIR_COLUMNS = ["pair_id", "incident", "option_a", "option_b", "preferred"]
Decision = Literal["enabled_by_configuration", "templates_only", "not_measurable"]


def narrative_text(output: Mapping[str, Any]) -> str:
    """The narrative as plain text for the pairwise sheet (pseudonyms kept, citations shown)."""
    lines = [str(output["summary"]), "Observed:"]
    lines += [f"- {o['statement']} [{', '.join(o['evidence_ids'])}]" for o in output["observed"]]
    lines.append("Inferences:")
    for i in output["inferences"]:
        ids = [*i["supporting_ids"], *i.get("knowledge_ids", [])]
        lines.append(f"- {i['statement']} ({i['confidence']}) [{', '.join(ids)}]")
        lines.append("  could also be: " + "; ".join(i["alternative_explanations"]))
    lines.append("Suggested checks:")
    lines += [
        f"- {r['action']} [{', '.join(r['rationale_ids'])}]" for r in output["recommendations"]
    ]
    lines.append("Open questions:")
    lines += [f"- {q}" for q in output["open_questions"]]
    return "\n".join(lines)


def cited_evidence(pack: Mapping[str, Any], ids: Sequence[str]) -> dict[str, Any]:
    """What a rater needs to judge a citation: the cited pack items themselves."""
    findings = {f["fid"]: f for f in pack["findings"]}
    shown: dict[str, Any] = {}
    for cid in ids:
        if cid.startswith("E-"):
            shown[cid] = pack["evidence"].get(cid)
        elif cid.startswith("F-"):
            shown[cid] = findings.get(cid)
        else:
            shown[cid] = str(pack["knowledge"].get(cid, ""))[:300]
    return shown


def build_sheets(
    records: Sequence[Mapping[str, Any]], seed: int
) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, Any]]:
    """Blinded statement and pairwise sheets for the validated narratives, plus the answer key.

    Item order and the A/B position are randomised with `seed`; the incident column is a blinded
    label (N001...), so a rater cannot tell which run or finding type an item belongs to.
    """
    rng = random.Random(seed)  # noqa: S311  (shuffling an audit sheet, not cryptography)
    validated = [r for r in records if r["status"] == "validated" and r.get("output")]
    labels = {f"{r['run_id']}/{r['incident']}": f"N{n:03d}" for n, r in enumerate(validated, 1)}
    statements: list[dict[str, str]] = []
    pairs: list[dict[str, str]] = []
    key: dict[str, Any] = {"seed": seed, "incidents": {}, "pairs": {}}
    for r in validated:
        label = labels[f"{r['run_id']}/{r['incident']}"]
        key["incidents"][label] = f"{r['run_id']}/{r['incident']}"
        out = r["output"]
        rows: list[tuple[str, str, list[str]]] = [
            ("observed", o["statement"], list(o["evidence_ids"])) for o in out["observed"]
        ] + [
            (
                "inference",
                i["statement"],
                [*i["supporting_ids"], *i.get("knowledge_ids", [])],
            )
            for i in out["inferences"]
        ]
        for kind, text, ids in rows:
            statements.append(
                {
                    "item_id": "",
                    "incident": label,
                    "kind": kind,
                    "text": text,
                    "cited": " ".join(ids),
                    "cited_evidence": json.dumps(cited_evidence(r["pack"], ids), sort_keys=True),
                    "supported": "",
                    "citation_correct": "",
                }
            )
        template_first = rng.random() < 0.5
        narrative = narrative_text(out)
        a, b = (r["template"], narrative) if template_first else (narrative, r["template"])
        pairs.append(
            {"pair_id": "", "incident": label, "option_a": a, "option_b": b, "preferred": ""}
        )
        key["pairs"][label] = {"narrative_is": "b" if template_first else "a"}
    rng.shuffle(statements)
    rng.shuffle(pairs)
    for n, row in enumerate(statements, 1):
        row["item_id"] = f"S{n:04d}"
    for n, prow in enumerate(pairs, 1):
        prow["pair_id"] = f"P{n:03d}"
        key["pairs"][prow["pair_id"]] = key["pairs"].pop(prow["incident"])
    return statements, pairs, key


def write_sheets(
    out_dir: Path,
    statements: Sequence[Mapping[str, str]],
    pairs: Sequence[Mapping[str, str]],
    key: Mapping[str, Any],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, columns, rows in (
        ("statements-TEMPLATE.csv", STATEMENT_COLUMNS, statements),
        ("pairs-TEMPLATE.csv", PAIR_COLUMNS, pairs),
    ):
        with (out_dir / name).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
    (out_dir / "answer_key.json").write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")


def read_sheet(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def score(
    records: Sequence[Mapping[str, Any]],
    statement_sheets: Mapping[str, Iterable[Mapping[str, str]]],
    pair_sheets: Mapping[str, Iterable[Mapping[str, str]]],
    key: Mapping[str, Any],
) -> dict[str, Any]:
    """G2 metrics from the generation records and the completed sheets (None = not measured)."""
    counts = {s: sum(1 for r in records if r["status"] == s) for s in ("validated", "rejected")}
    unavailable = sum(1 for r in records if r["status"] == "unavailable")
    pass_rate = _rate(counts["validated"], counts["validated"] + counts["rejected"])

    observed_yes = observed_total = inference_no = inference_total = 0
    cite_yes = cite_total = 0
    for rows in statement_sheets.values():
        for row in rows:
            supported = row.get("supported", "").strip().lower()
            if supported in ("yes", "no"):
                if row["kind"] == "observed":
                    observed_total += 1
                    observed_yes += supported == "yes"
                else:
                    inference_total += 1
                    inference_no += supported == "no"
            citation = row.get("citation_correct", "").strip().lower()
            if citation in ("yes", "no"):
                cite_total += 1
                cite_yes += citation == "yes"

    narrative_wins = rated_pairs = 0
    for rows in pair_sheets.values():
        for row in rows:
            choice = row.get("preferred", "").strip().lower()
            if choice not in ("a", "b", "tie"):
                continue
            rated_pairs += 1
            narrative_wins += choice == key["pairs"][row["pair_id"]]["narrative_is"]
    return {
        "incidents_with_model_outcome": counts["validated"] + counts["rejected"],
        "validated": counts["validated"],
        "rejected": counts["rejected"],
        "unavailable": unavailable,
        "validator_pass_rate": pass_rate,
        "observed_support": _rate(observed_yes, observed_total),
        "observed_rated": observed_total,
        "unsupported_inferences": _rate(inference_no, inference_total),
        "inferences_rated": inference_total,
        "citation_correctness": _rate(cite_yes, cite_total),
        "citations_rated": cite_total,
        "preference": _rate(narrative_wins, rated_pairs),
        "pairs_rated": rated_pairs,
        "raters": len(set(statement_sheets) | set(pair_sheets)),
    }


def decide_g2(metrics: Mapping[str, Any]) -> tuple[Decision, str]:
    """Apply the pre-declared rule to measured numbers, or say that it cannot be applied."""
    missing = [
        name
        for name in (
            "validator_pass_rate",
            "observed_support",
            "unsupported_inferences",
            "citation_correctness",
            "preference",
        )
        if metrics.get(name) is None
    ]
    if metrics.get("incidents_with_model_outcome", 0) < MIN_INCIDENTS:
        return "not_measurable", f"fewer than {MIN_INCIDENTS} incidents have a model outcome"
    if metrics.get("unavailable", 0):
        return "not_measurable", "the provider failed for some incidents (not a model outcome)"
    if metrics.get("raters", 0) < MIN_RATERS:
        return "not_measurable", f"fewer than {MIN_RATERS} raters completed sheets"
    if missing:
        return "not_measurable", "no ratings for: " + ", ".join(missing)
    failed = [
        label
        for label, ok in (
            ("validator pass rate", metrics["validator_pass_rate"] >= PASS_RATE_MIN),
            ("observed support", metrics["observed_support"] >= OBSERVED_SUPPORT_MIN),
            (
                "unsupported inferences",
                metrics["unsupported_inferences"] <= UNSUPPORTED_INFERENCE_MAX,
            ),
            ("citation correctness", metrics["citation_correctness"] >= CITATION_CORRECT_MIN),
            ("preference", metrics["preference"] >= PREFERENCE_MIN),
        )
        if not ok
    ]
    if failed:
        return "templates_only", "below the pre-declared threshold: " + ", ".join(failed)
    return "enabled_by_configuration", "every pre-declared G2 threshold was met"
