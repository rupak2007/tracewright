"""Finding-to-episode matching and detector metrics (eval/PROTOCOL.md §3, §6). Pure functions.

A finding MATCHES an episode when
  1. entity: SCAN/BRUTE: the finding's primary entity is the episode actor or one of its secondary
     entities is an episode target; DNSTUN/BEACON/EXFIL: the primary entity (the affected internal
     host) is the episode actor or one of its targets. PROTOCOL §3 says "the affected internal
     host" without saying whether labels record that host as actor or target; both are accepted
     until real attack labels exist, and this is flagged in eval/datasets.md;
  2. time: [start_ts, end_ts] overlaps [episode.start - 60 s, episode.end + 60 s];
  3. class: for an `attack` episode the finding type equals the episode class. A hard-negative
     episode matches on entity and time alone, because no detector class exists for it: a finding
     on it is a false positive attributed to that hard-negative class.
An attack episode is DETECTED when at least one finding matches it. A finding that matches no
attack episode is a false positive (in a capture where every attack is labelled).

Precision and recall are only defined when there is something to divide by; with no attack episode
the result says so (None) instead of reporting a number.
"""

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from lab.schema import Episode

TOLERANCE = timedelta(seconds=60)
ENTITY_BY_TARGET = ("DNSTUN", "BEACON", "EXFIL")  # affected host may be recorded as a target


@dataclass(frozen=True)
class FindingView:
    """The few finding fields matching needs (decoupled from the pydantic model)."""

    id: str
    type: str
    primary_entity: str
    secondary_entities: tuple[str, ...]
    start_ts: Any  # datetime
    end_ts: Any
    confidence: str


def entity_matches(finding: FindingView, episode: Episode) -> bool:
    if finding.primary_entity == episode.actor:
        return True
    if finding.type in ENTITY_BY_TARGET:
        return finding.primary_entity in episode.targets
    return any(s in episode.targets for s in finding.secondary_entities)


def time_matches(finding: FindingView, episode: Episode) -> bool:
    return bool(
        finding.start_ts <= episode.end + TOLERANCE and finding.end_ts >= episode.start - TOLERANCE
    )


def matches(finding: FindingView, episode: Episode) -> bool:
    if episode.kind == "attack" and finding.type != episode.cls:
        return False
    return entity_matches(finding, episode) and time_matches(finding, episode)


@dataclass
class RunEvaluation:
    """Matching outcome for the findings of one or more runs."""

    attack_episodes: Counter[str] = field(default_factory=Counter)
    detected: Counter[str] = field(default_factory=Counter)
    # findings matching no attack episode: [(finding id, type, confidence, matched hard negative)]
    false_positives: list[tuple[str, str, str, str | None]] = field(default_factory=list)
    findings: int = 0

    def merge(self, other: "RunEvaluation") -> None:
        self.attack_episodes.update(other.attack_episodes)
        self.detected.update(other.detected)
        self.false_positives += other.false_positives
        self.findings += other.findings


def evaluate_run(findings: Sequence[FindingView], episodes: Iterable[Episode]) -> RunEvaluation:
    eps = list(episodes)
    result = RunEvaluation(findings=len(findings))
    attacks = [e for e in eps if e.kind == "attack"]
    hard_negatives = [e for e in eps if e.kind == "hard_negative"]
    for e in attacks:
        result.attack_episodes[e.cls] += 1
        if any(matches(f, e) for f in findings):
            result.detected[e.cls] += 1
    for f in findings:
        if any(matches(f, e) for e in attacks):
            continue
        hit = next((h.cls for h in hard_negatives if matches(f, h)), None)
        result.false_positives.append((f.id, f.type, f.confidence, hit))
    return result


def ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def summarise(
    evaluation: RunEvaluation,
    benign_hours: float,
    min_confidence: Sequence[str] = ("medium", "high"),
) -> dict[str, Any]:
    """Metrics for reports. Anything without a denominator is None, never 0."""
    counted = [fp for fp in evaluation.false_positives if fp[2] in min_confidence]
    by_hard_negative = Counter(fp[3] or "unlabelled" for fp in counted)
    by_type = Counter(fp[1] for fp in counted)
    total_episodes = sum(evaluation.attack_episodes.values())
    total_detected = sum(evaluation.detected.values())
    true_positive_findings = evaluation.findings - len(evaluation.false_positives)
    return {
        "findings": evaluation.findings,
        "attack_episodes": dict(sorted(evaluation.attack_episodes.items())),
        "episodes_detected": dict(sorted(evaluation.detected.items())),
        "recall": ratio(total_detected, total_episodes),
        "precision": ratio(true_positive_findings, evaluation.findings) if total_episodes else None,
        "false_positive_findings_all_confidence": len(evaluation.false_positives),
        "false_positive_findings_medium_high": len(counted),
        "false_positive_by_type_medium_high": dict(sorted(by_type.items())),
        "false_positive_by_hard_negative_medium_high": dict(sorted(by_hard_negative.items())),
        "benign_hours": round(benign_hours, 4),
        "false_positives_per_benign_hour_medium_high": ratio_float(len(counted), benign_hours),
    }


def ratio_float(numerator: float, denominator: float) -> float | None:
    return None if denominator <= 0 else round(numerator / denominator, 4)
