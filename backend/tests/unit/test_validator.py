"""The narrative validator, with hand-written bad and good outputs (plan P8 testing list)."""

import copy
import json
from typing import Any

import pytest

from app.explain.evidence_pack import EvidencePack
from app.explain.validator import validate_narrative

PACK = EvidencePack(
    pack={
        "incident": {
            "id": "I-1",
            "severity": "high",
            "span": "T+00:00:00 to T+00:41:55",
            "types": ["BEACON", "EXFIL"],
        },
        "capture": {
            "span_min": 58.0,
            "warnings": ["ONE_SIDED_TRAFFIC"],
            "max_beacon_interval_s": 348.0,
        },
        "entities": {"H1": "internal", "X1": "external", "D1": "domain"},
        "findings": [
            {
                "fid": "F-1",
                "type": "BEACON",
                "confidence": "high",
                "entity": "H1",
                "peers": ["X1"],
                "metrics": {
                    "events": 37,
                    "median_interval_s": 60.2,
                    "beacon_score": 0.93,
                    "dst_port": 443,
                },
                "thresholds": {"min_events": 10, "min_score": 0.8},
                "evidence": ["E-1", "E-2"],
                "summary_item": "E-1",
                "techniques": ["T1071.001"],
            }
        ],
        "evidence": {
            "E-1": {
                "kind": "aggregate",
                "fields": {
                    "events": 37,
                    "median_interval_s": 60.2,
                    "beacon_score": 0.93,
                    "threshold_min_events": 10,
                    "confidence": "high",
                    "start": "T+00:02:10",
                    "end": "T+00:41:55",
                },
            },
            "E-2": {
                "kind": "conn",
                "fields": {
                    "t": "T+00:02:10",
                    "src": "H1",
                    "dst": "X1",
                    "dst_port": 443,
                    "bytes_out": 412,
                    "bytes_in": 3_000_000,
                    "state": "SF",
                },
            },
        },
        "knowledge": {
            "K-T1071.001": "Web Protocols: ...",
            "K-PB-DET-BEACON": "What the detector saw ...",
        },
        "links": [],
    },
    mapping={"H1": "10.0.0.5", "X1": "203.0.113.9", "D1": "updates.example.com"},
)

GOOD: dict[str, Any] = {
    "summary": "A regular check-in pattern from H1 to X1 that deserves a closer look.",
    "observed": [
        {
            "statement": (
                "H1 contacted X1 on port 443 37 times at a median interval of 60.2 s "
                "(beacon score 0.93)."
            ),
            "evidence_ids": ["E-1", "E-2"],
        },
        {
            "statement": "The first connection was at T+00:02:10 and sent 412 bytes.",
            "evidence_ids": ["E-2"],
        },
    ],
    "inferences": [
        {
            "statement": "The timing is consistent with an automated check-in.",
            "supporting_ids": ["E-1", "F-1"],
            "knowledge_ids": ["K-T1071.001"],
            "confidence": "medium",
            "alternative_explanations": ["a software update or monitoring agent polling a vendor"],
        }
    ],
    "recommendations": [
        {
            "action": "Compare the interval with the agents installed on H1.",
            "rationale_ids": ["E-1", "K-PB-DET-BEACON"],
        }
    ],
    "open_questions": ["Is X1 a vendor the organisation uses?"],
}


def check(output: dict[str, Any] | str) -> list[str]:
    raw = output if isinstance(output, str) else json.dumps(output)
    result = validate_narrative(raw, PACK)
    assert result.ok == (not result.errors) and (result.output is not None) == result.ok
    return result.errors


def mutated(**changes: Any) -> dict[str, Any]:
    out = copy.deepcopy(GOOD)
    out.update(changes)
    return out


def test_a_correct_narrative_passes() -> None:
    assert check(GOOD) == []


def test_a_json_code_fence_is_tolerated_but_prose_around_json_is_not() -> None:
    assert check("```json\n" + json.dumps(GOOD) + "\n```") == []
    assert check("Here you go: " + json.dumps(GOOD))[0].startswith("check 1")


# ---- check 1: schema --------------------------------------------------------------------
def test_not_json_and_schema_violations_are_rejected() -> None:
    assert check("not json at all")[0].startswith("check 1: the output is not valid JSON")
    missing = {k: v for k, v in GOOD.items() if k != "summary"}
    assert "summary" in check(missing)[0]
    assert check(mutated(extra_field="x"))[0].startswith("check 1")
    no_citation = copy.deepcopy(GOOD)
    no_citation["observed"][0]["evidence_ids"] = []
    assert check(no_citation)[0].startswith("check 1")
    bad_conf = copy.deepcopy(GOOD)
    bad_conf["inferences"][0]["confidence"] = "certain"
    assert check(bad_conf)[0].startswith("check 1")


# ---- check 2: ids -----------------------------------------------------------------------
@pytest.mark.parametrize(
    ("ids", "fragment"),
    [
        (["E-99"], "E-99, which is not in the evidence pack"),
        (["F-9"], "F-9, which is not a finding of this incident"),
        (["X-1"], "not an E-/F-/K- id"),
    ],
)
def test_unknown_evidence_or_finding_ids_are_rejected(ids: list[str], fragment: str) -> None:
    out = copy.deepcopy(GOOD)
    out["observed"][1]["evidence_ids"] = ids
    assert any(fragment in e for e in check(out))


def test_knowledge_ids_must_belong_to_this_incident() -> None:
    out = copy.deepcopy(GOOD)
    out["inferences"][0]["knowledge_ids"] = ["K-T1046"]
    assert any("K-T1046" in e and "not a technique or playbook" in e for e in check(out))
    out["inferences"][0]["knowledge_ids"] = ["E-1"]
    assert any("must be K- ids" in e for e in check(out))
    out["inferences"][0]["knowledge_ids"] = ["K-PB-DET-BEACON"]
    assert check(out) == []


def test_observed_statements_may_cite_evidence_or_findings_only() -> None:
    out = copy.deepcopy(GOOD)
    out["observed"][0]["evidence_ids"] = ["K-T1071.001"]
    assert any("must cite E- or F- ids only" in e for e in check(out))
    out["observed"][0] = {"statement": "H1 reported 37 events.", "evidence_ids": ["F-1"]}
    assert check(out) == []  # a finding's own metrics count as its evidence


# ---- check 3: entities, times, numbers --------------------------------------------------
def test_an_invented_host_token_is_rejected_everywhere() -> None:
    out = copy.deepcopy(GOOD)
    out["observed"][0]["statement"] = "H9 contacted X1 on port 443."
    assert any("H9" in e and "not in the pack" in e for e in check(out))
    out = copy.deepcopy(GOOD)
    out["summary"] = "D7 looks odd."
    assert any("D7" in e for e in check(out))


def test_a_token_missing_from_the_cited_evidence_is_rejected() -> None:
    out = copy.deepcopy(GOOD)
    out["observed"][1] = {"statement": "D1 was contacted.", "evidence_ids": ["E-2"]}
    assert any("D1" in e and "cited evidence" in e for e in check(out))


def test_numbers_must_match_the_cited_evidence_within_one_percent() -> None:
    def observed(statement: str) -> list[str]:
        out = copy.deepcopy(GOOD)
        out["observed"] = [{"statement": statement, "evidence_ids": ["E-1", "E-2"]}]
        return check(out)

    assert observed("H1 sent 412 bytes to X1.") == []
    assert observed("H1 made 38 connections.") != []  # 37 stored, 38 stated (+2.7%)
    assert observed("The median interval was 60 s.") == []  # 60.2: within 1%
    assert observed("The median interval was 61 s.") != []  # 61 vs 60.2: 1.3% off
    assert observed("H1 sent 413 bytes.") == []  # 412: 0.24% off
    assert observed("The beacon score was 0.93.") == []
    assert observed("The beacon score was 0.5.") != []
    assert observed("It used port 443.") == [] and observed("It used port 444.") != []


def test_units_are_normalised_for_percent_bytes_and_time() -> None:
    def observed(statement: str) -> list[str]:
        out = copy.deepcopy(GOOD)
        out["observed"] = [{"statement": statement, "evidence_ids": ["E-1", "E-2"]}]
        return check(out)

    assert observed("The score was 93%.") == []  # stored as 0.93
    assert observed("The score was 50%.") != []
    assert observed("About 3 MB came back.") == []  # 3,000,000 bytes
    assert observed("About 2.86 MiB came back.") == []  # 3,000,000 / 1,048,576 = 2.861
    assert observed("About 3 GB came back.") != []
    assert observed("The interval was 1 min.") == []  # 60.2 s
    assert observed("The interval was 2 min.") != []
    assert observed("The first seen T+00:02:10, last T+00:41:55.") == []
    assert any("T+00:09:00" in e for e in observed("It started at T+00:09:00."))


def test_identifiers_inside_a_statement_are_not_mistaken_for_numbers() -> None:
    out = copy.deepcopy(GOOD)
    out["observed"][0]["statement"] = "H1 (see E-1, F-1 and T1071.001) contacted X1 37 times."
    assert check(out) == []


# ---- check 4: hedging -------------------------------------------------------------------
def test_an_inference_without_an_alternative_is_rejected() -> None:
    out = copy.deepcopy(GOOD)
    out["inferences"][0]["alternative_explanations"] = []
    assert check(out)[0].startswith("check 1")  # the schema already forbids an empty list
    out["inferences"][0]["alternative_explanations"] = ["   "]
    assert any("check 4" in e for e in check(out))


# ---- check 5: verdict language ----------------------------------------------------------
@pytest.mark.parametrize(
    "phrase",
    [
        "H1 is compromised.",
        "H1 has been compromised.",
        "This is a confirmed attack.",
        "It is definitely malware.",
        "This proves exfiltration.",
        "H1 is infected.",
        "Without a doubt it is C2.",
    ],
)
def test_verdict_language_is_rejected_in_any_field(phrase: str) -> None:
    for field in ("summary", "open_questions"):
        out = copy.deepcopy(GOOD)
        out[field] = phrase if field == "summary" else [phrase]
        assert any("check 5" in e for e in check(out)), (field, phrase)
    out = copy.deepcopy(GOOD)
    out["inferences"][0]["statement"] = phrase
    assert any("check 5" in e for e in check(out))


def test_ordinary_hedged_wording_is_not_flagged() -> None:
    out = copy.deepcopy(GOOD)
    out["summary"] = "This could be a proven vendor agent; the evidence does not decide it."
    assert check(out) == []  # "proven" is not "proves"


# ---- check 6: real values ---------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "H1 talked to 203.0.113.9.",
        "The host 10.0.0.5 beacons.",
        "It resolved updates.example.com.",
        "Seen at 2001:db8::1:2.",
    ],
)
def test_real_addresses_and_domains_are_rejected(text: str) -> None:
    out = copy.deepcopy(GOOD)
    out["summary"] = text
    assert any("check 6" in e for e in check(out))


def test_a_real_value_from_the_server_side_mapping_is_rejected_even_without_a_pattern_match() -> (
    None
):
    out = copy.deepcopy(GOOD)
    out["open_questions"] = ["Is updates.example.com the vendor?"]
    assert any("check 6" in e for e in check(out))
    pack = EvidencePack(PACK.pack, {"H1": "nasbox"})
    out = copy.deepcopy(GOOD)
    out["summary"] = "The nasbox host beacons."
    result = validate_narrative(json.dumps(out), pack)
    assert any("real host or domain" in e for e in result.errors)


def test_technique_ids_and_decimal_numbers_are_not_mistaken_for_domains() -> None:
    out = copy.deepcopy(GOOD)
    out["summary"] = "Consistent with T1071.001, score 0.93, e.g. a check-in."
    assert check(out) == []


def test_every_failed_check_is_reported_together_for_the_repair_attempt() -> None:
    out = copy.deepcopy(GOOD)
    out["summary"] = "H1 is compromised and talks to 203.0.113.9."
    out["observed"][0]["evidence_ids"] = ["E-99"]
    errors = check(out)
    assert {"check 2", "check 5", "check 6"} <= {e.split(":")[0] for e in errors}
