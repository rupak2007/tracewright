"""Gate G2 tooling. SYNTHETIC records, ratings and a scripted provider: not a G2 result."""

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("eval")
pytest.importorskip("lab")

from eval import llm_eval, run_llm, score_llm
from eval import splits as splits_module

from app.explain.llm_client import NoneClient
from tests.unit.test_eval_run_detectors import write_analysis
from tests.unit.test_eval_splits import manifest, write_run
from tests.unit.test_narrative import Scripted


class PackAwareClient:
    """Answers with a narrative that is valid for whatever pack it is shown."""

    provider, model = "scripted", "s-1"

    def generate(self, system: str, user: str) -> str:
        pack = json.loads(user.split("Evidence pack:\n", 1)[1].split("\n\nYour previous", 1)[0])
        first = pack["findings"][0]
        return json.dumps(
            {
                "summary": f"{first['entity']} shows a pattern worth a closer look.",
                "observed": [
                    {
                        "statement": f"{first['entity']} was flagged by one detector.",
                        "evidence_ids": [first["fid"]],
                    }
                ],
                "inferences": [
                    {
                        "statement": "This could be routine automation.",
                        "supporting_ids": [first["fid"]],
                        "knowledge_ids": [],
                        "confidence": "low",
                        "alternative_explanations": ["a scheduled job"],
                    }
                ],
                "recommendations": [
                    {"action": "Check the scheduled jobs.", "rationale_ids": [first["fid"]]}
                ],
                "open_questions": ["Is this expected?"],
            }
        )


@pytest.fixture
def world(tmp_path: Path) -> dict[str, Any]:
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    write_run(runs_dir, "d1", [("hard_negative", "MONITORING_HEARTBEAT", "")])
    write_run(runs_dir, "t1", [("hard_negative", "NTP", "")])
    assigned = {
        "d1": {"split": "dev", "stratum": "s", "labels_sha256": "x", "run_json_sha256": "x"},
        "t1": {"split": "test", "stratum": "s", "labels_sha256": "x", "run_json_sha256": "x"},
    }
    analysis = tmp_path / "analysis"
    write_analysis(analysis, "d1")
    return {
        "runs": splits_module.load_runs(runs_dir),
        "manifest": manifest(assigned),
        "analysis": analysis,
        "tmp": tmp_path,
    }


def generate(world: dict[str, Any], client: Any, split: str = "dev") -> Any:
    return run_llm.generate_split(
        split,
        world["analysis"],
        client,
        seed=7,
        manifest=world["manifest"],
        runs=world["runs"],
    )


def test_generation_runs_the_product_stages_and_validates(world: dict[str, Any]) -> None:
    records, run_manifest = generate(world, PackAwareClient())
    assert len(records) == 1 and records[0]["status"] == "validated"
    assert records[0]["incident"].startswith("I-") and records[0]["template"]
    assert records[0]["pack"]["findings"][0]["type"] == "BEACON"
    assert run_manifest["purpose"] == "pipeline_check_not_a_g2_evaluation"
    assert run_manifest["provider"] == "scripted" and len(run_manifest["prompt_hash"]) == 64
    real = {"172.20.0.101", "172.20.0.20"}
    assert not any(ip in json.dumps(records[0]["pack"]) for ip in real)


def test_the_test_split_is_refused_until_the_corpus_is_complete(world: dict[str, Any]) -> None:
    with pytest.raises(run_llm.HarnessError, match="refusing to evaluate the test split"):
        generate(world, PackAwareClient(), "test")


def test_rejected_and_unavailable_outcomes_are_recorded_not_dropped(world: dict[str, Any]) -> None:
    bad = json.dumps({"summary": "x"})
    records, _ = generate(world, Scripted(bad, bad))
    assert records[0]["status"] == "rejected" and records[0]["attempts"] == 2
    records, _ = generate(world, NoneClient())
    assert records[0]["status"] == "unavailable" and records[0]["output"] is None


def test_outputs_are_written_once_and_never_overwritten(world: dict[str, Any]) -> None:
    records, run_manifest = generate(world, PackAwareClient())
    out, audit = world["tmp"] / "results", world["tmp"] / "audit"
    target = run_llm.write_outputs(records, run_manifest, "g2-dev", out, audit)
    assert (target / "llm_narratives.json").exists() and (target / "manifest.json").exists()
    assert {p.name for p in (audit / "g2-dev").iterdir()} == {
        "statements-TEMPLATE.csv",
        "pairs-TEMPLATE.csv",
        "answer_key.json",
    }
    with pytest.raises(run_llm.HarnessError, match="never overwritten"):
        run_llm.write_outputs(records, run_manifest, "g2-dev", out, audit)


def test_the_cli_refuses_provider_none_and_reports_harness_errors(
    world: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_llm.main(["--split", "dev", "--run-id", "x"], client_factory=NoneClient) == 2
    assert "no model to evaluate" in capsys.readouterr().err


# ---- sheets ----------------------------------------------------------------------------
def fake_records(n: int, status: str = "validated") -> list[dict[str, Any]]:
    pack = {
        "findings": [{"fid": "F-1"}],
        "evidence": {"E-1": {"kind": "aggregate", "fields": {"events": 3}}},
        "knowledge": {},
    }
    output = {
        "summary": "S",
        "observed": [{"statement": "obs", "evidence_ids": ["E-1"]}],
        "inferences": [
            {
                "statement": "inf",
                "supporting_ids": ["E-1"],
                "knowledge_ids": [],
                "confidence": "low",
                "alternative_explanations": ["alt"],
            }
        ],
        "recommendations": [],
        "open_questions": [],
    }
    return [
        {
            "run_id": f"run{n % 3}",
            "incident": f"I-{n}",
            "pack": pack,
            "template": f"template {n}",
            "status": status,
            "attempts": 1,
            "reasons": [],
            "output": output if status == "validated" else None,
            "raw_output": "",
        }
        for n in range(n)
    ]


def test_sheets_are_blinded_randomised_and_reproducible() -> None:
    records = fake_records(12)
    s1, p1, k1 = llm_eval.build_sheets(records, seed=3)
    s2, p2, k2 = llm_eval.build_sheets(records, seed=3)
    assert (s1, p1, k1) == (s2, p2, k2)
    assert llm_eval.build_sheets(records, seed=4)[1] != p1
    blob = json.dumps([s1, p1])
    assert "run0" not in blob and "I-3" not in blob  # no run id or incident id for raters
    assert len(s1) == 24 and len(p1) == 12  # one observed + one inference per narrative
    assert {r["item_id"] for r in s1} == {f"S{n:04d}" for n in range(1, 25)}
    positions = [k1["pairs"][p["pair_id"]]["narrative_is"] for p in p1]
    assert set(positions) == {"a", "b"}  # both orders occur
    for pair in p1:
        narrative_side = k1["pairs"][pair["pair_id"]]["narrative_is"]
        assert pair["option_" + narrative_side].startswith("S\nObserved:")
    assert all(r["supported"] == "" and r["citation_correct"] == "" for r in s1)


def test_only_validated_narratives_reach_the_raters() -> None:
    mixed = fake_records(3) + fake_records(2, "rejected") + fake_records(1, "unavailable")
    statements, pairs, _ = llm_eval.build_sheets(mixed, seed=1)
    assert len(pairs) == 3 and len(statements) == 6


# ---- scoring and the rule ----------------------------------------------------------------
def rated(
    records: list[dict[str, Any]],
    seed: int = 1,
    support: str = "yes",
    prefer_narrative: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    statements, pairs, key = llm_eval.build_sheets(records, seed)
    for row in statements:
        row["supported"], row["citation_correct"] = support, "yes"
    for pair in pairs:
        side = key["pairs"][pair["pair_id"]]["narrative_is"]
        other = "a" if side == "b" else "b"
        pair["preferred"] = side if prefer_narrative else other
    return (
        {"r1": statements, "r2": statements, "r3": statements},
        {
            "r1": pairs,
            "r2": pairs,
            "r3": pairs,
        },
        key,
    )


def test_every_threshold_met_enables_by_configuration() -> None:
    records = fake_records(30)
    st, pr, key = rated(records)
    metrics = llm_eval.score(records, st, pr, key)
    assert metrics["validator_pass_rate"] == 1.0 and metrics["raters"] == 3
    assert metrics["preference"] == 1.0 and metrics["observed_support"] == 1.0
    assert llm_eval.decide_g2(metrics)[0] == "enabled_by_configuration"


def test_a_missed_threshold_means_templates_only_and_names_it() -> None:
    records = fake_records(30)
    st, pr, key = rated(records, prefer_narrative=False)
    decision, why = llm_eval.decide_g2(llm_eval.score(records, st, pr, key))
    assert decision == "templates_only" and "preference" in why
    st, pr, key = rated(records, support="no")
    decision, why = llm_eval.decide_g2(llm_eval.score(records, st, pr, key))
    assert decision == "templates_only" and "observed support" in why
    assert "unsupported inferences" in why


def test_ties_and_the_validator_pass_rate_follow_the_documented_interpretation() -> None:
    records = fake_records(27) + fake_records(3, "rejected")
    st, pr, key = rated(records)
    for rows in pr.values():
        for row in rows[:2]:
            row["preferred"] = "tie"  # a tie never counts as a preference for the narrative
    metrics = llm_eval.score(records, st, pr, key)
    assert metrics["validator_pass_rate"] == 0.9  # 27 / (27 + 3)
    assert metrics["preference"] is not None and metrics["preference"] < 1.0
    assert metrics["rejected"] == 3 and metrics["incidents_with_model_outcome"] == 30


@pytest.mark.parametrize(
    ("records", "raters", "fragment"),
    [
        (fake_records(29), 3, "fewer than 30"),
        (fake_records(30), 2, "fewer than 3 raters"),
        (fake_records(29) + fake_records(1, "unavailable"), 3, "fewer than 30"),
        (fake_records(30) + fake_records(1, "unavailable"), 3, "provider failed"),
    ],
)
def test_too_little_data_is_not_measurable_never_passed_or_failed(
    records: list[dict[str, Any]], raters: int, fragment: str
) -> None:
    st, pr, key = rated([r for r in records if r["status"] == "validated"])
    keep = [f"r{n}" for n in range(1, raters + 1)]
    st, pr = {k: st[k] for k in keep}, {k: pr[k] for k in keep}
    decision, why = llm_eval.decide_g2(llm_eval.score(records, st, pr, key))
    assert decision == "not_measurable" and fragment in why


def test_unrated_sheets_are_not_measurable_and_there_are_no_default_numbers() -> None:
    records = fake_records(30)
    statements, pairs, key = llm_eval.build_sheets(records, 1)
    metrics = llm_eval.score(
        records,
        {"r1": statements, "r2": statements, "r3": statements},
        {"r1": pairs, "r2": pairs, "r3": pairs},
        key,
    )
    assert metrics["observed_support"] is None and metrics["preference"] is None
    decision, why = llm_eval.decide_g2(metrics)
    assert decision == "not_measurable" and "no ratings for" in why


# ---- score_llm CLI ---------------------------------------------------------------------
def test_score_cli_ignores_templates_and_refuses_a_dev_or_unmeasurable_decision(
    world: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    records, run_manifest = generate(world, PackAwareClient())
    out, audit = world["tmp"] / "results", world["tmp"] / "audit"
    run_llm.write_outputs(records, run_manifest, "g2-dev", out, audit)
    argv = ["--run-id", "g2-dev", "--out", str(out), "--audit-dir", str(audit)]
    assert score_llm.main(argv) == 0
    result = json.loads((out / "g2-dev" / "g2.json").read_text(encoding="utf-8"))
    assert result["decision"] == "not_measurable" and result["metrics"]["raters"] == 0
    capsys.readouterr()
    assert score_llm.main([*argv, "--write-decision"]) == 2
    assert "not measurable" in capsys.readouterr().err
    assert not (Path(score_llm.__file__).parent / "decisions" / "G2.md.tmp").exists()


def test_score_cli_reports_a_missing_run(
    world: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    code = score_llm.main(
        ["--run-id", "nope", "--out", str(world["tmp"]), "--audit-dir", str(world["tmp"])]
    )
    assert code == 2 and "run eval.run_llm first" in capsys.readouterr().err


def test_the_decision_record_states_numbers_rule_and_default() -> None:
    metrics = llm_eval.score(fake_records(30), *rated(fake_records(30)))
    text = score_llm.decision_markdown("g2-test-1", metrics, "enabled_by_configuration", "why")
    assert "**enabled_by_configuration**" in text and ">= 0.90" in text and "g2-test-1" in text
    text = score_llm.decision_markdown("g2-test-1", metrics, "templates_only", "why")
    assert "`LLM_PROVIDER=none` (default)" in text
