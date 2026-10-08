"""Generate and validate one narrative: provider call, validator, one repair attempt, fallback.

Statuses: `validated` (shown, labelled machine-generated), `rejected` (twice invalid: the template
stays, raw output and reasons are kept for evaluation, GR-08), `unavailable` (provider off, down or
slow: the template stays). Unvalidated text never leaves this module as displayable output.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from app.explain.evidence_pack import EvidencePack
from app.explain.llm_client import LlmClient, LlmUnavailable
from app.explain.schema import NarrativeOutput
from app.explain.validator import validate_narrative

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "narrative_v1.txt"
NarrativeStatus = Literal["validated", "rejected", "unavailable"]


def system_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def prompt_hash() -> str:
    return hashlib.sha256(system_prompt().replace("\r\n", "\n").encode()).hexdigest()


def user_message(pack: EvidencePack) -> str:
    return "Evidence pack:\n" + pack.to_json()


def repair_message(pack: EvidencePack, previous: str, errors: list[str]) -> str:
    return (
        user_message(pack)
        + "\n\nYour previous answer was rejected by the validator for these reasons:\n- "
        + "\n- ".join(errors)
        + "\n\nPrevious answer:\n"
        + previous[:4000]
        + "\n\nFix every problem and reply with the corrected JSON object only."
    )


@dataclass
class NarrativeResult:
    status: NarrativeStatus
    output: NarrativeOutput | None = None
    raw_output: str = ""
    reasons: list[str] = field(default_factory=list)
    attempts: int = 0


def generate_narrative(pack: EvidencePack, client: LlmClient) -> NarrativeResult:
    """Call the provider, validate, repair once, else fall back; provider errors never raise."""
    system = system_prompt()
    try:
        first = client.generate(system, user_message(pack))
    except LlmUnavailable as exc:
        return NarrativeResult("unavailable", reasons=[str(exc)])
    checked = validate_narrative(first, pack)
    if checked.ok and checked.output is not None:
        return NarrativeResult("validated", checked.output, first, [], 1)
    try:
        second = client.generate(system, repair_message(pack, first, checked.errors))
    except LlmUnavailable as exc:
        return NarrativeResult(
            "unavailable",
            raw_output=first,
            reasons=[*checked.errors, f"repair attempt: {exc}"],
            attempts=1,
        )
    again = validate_narrative(second, pack)
    raw = json.dumps({"first_attempt": first, "second_attempt": second})
    if again.ok and again.output is not None:
        return NarrativeResult("validated", again.output, raw, [], 2)
    return NarrativeResult("rejected", None, raw, again.errors, 2)
