"""The narrative service: provider call, validation, one repair attempt, fallback."""

import json
from typing import Any

from app.explain.llm_client import LlmUnavailable
from app.explain.narrative import (
    generate_narrative,
    prompt_hash,
    repair_message,
    system_prompt,
    user_message,
)
from tests.unit.test_validator import GOOD, PACK


class Scripted:
    """Returns the scripted answers in order; an Exception entry is raised instead."""

    provider, model = "fake", "fake-1"

    def __init__(self, *answers: str | Exception) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, str]] = []

    def generate(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


BAD: dict[str, Any] = {**GOOD, "summary": "H1 is compromised."}


def test_a_valid_first_answer_needs_one_call() -> None:
    client = Scripted(json.dumps(GOOD))
    result = generate_narrative(PACK, client)
    assert result.status == "validated" and result.attempts == 1 and result.reasons == []
    assert result.output is not None and result.output.summary == GOOD["summary"]
    assert len(client.calls) == 1


def test_one_repair_attempt_then_validated() -> None:
    client = Scripted(json.dumps(BAD), json.dumps(GOOD))
    result = generate_narrative(PACK, client)
    assert result.status == "validated" and result.attempts == 2
    repair = client.calls[1][1]
    assert "check 5" in repair and "Previous answer" in repair and "Evidence pack" in repair
    assert json.loads(result.raw_output)["first_attempt"] == json.dumps(BAD)


def test_two_invalid_answers_are_rejected_and_the_raw_text_is_kept_for_evaluation() -> None:
    client = Scripted(json.dumps(BAD), "not json")
    result = generate_narrative(PACK, client)
    assert result.status == "rejected" and result.output is None and result.attempts == 2
    assert result.reasons and result.reasons[0].startswith("check 1")
    raw = json.loads(result.raw_output)
    assert raw["second_attempt"] == "not json" and "compromised" in raw["first_attempt"]
    assert len(client.calls) == 2  # never a third


def test_a_provider_that_is_off_or_down_is_unavailable_not_an_error() -> None:
    result = generate_narrative(PACK, Scripted(LlmUnavailable("off")))
    assert (result.status, result.output, result.reasons) == ("unavailable", None, ["off"])
    assert result.attempts == 0


def test_a_provider_failing_on_the_repair_call_keeps_the_first_failure_reasons() -> None:
    result = generate_narrative(PACK, Scripted(json.dumps(BAD), LlmUnavailable("timeout")))
    assert result.status == "unavailable" and result.attempts == 1
    assert any("check 5" in r for r in result.reasons)
    assert result.reasons[-1] == "repair attempt: timeout"
    assert json.dumps(BAD) == result.raw_output


def test_the_prompt_is_versioned_and_the_user_message_carries_only_the_pack() -> None:
    assert len(prompt_hash()) == 64 and prompt_hash() == prompt_hash()
    assert "evidence" in system_prompt().lower()
    message = user_message(PACK)
    assert message.startswith("Evidence pack:\n")
    for real in PACK.mapping.values():  # the client never sees the real values
        assert real not in message and real not in repair_message(PACK, "x", ["e"])
