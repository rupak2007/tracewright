"""Documented severity formula (architecture §9): an ordering aid, not a risk score. Pure."""

from collections.abc import Collection

from app.correlate.config import SeverityConfig
from app.correlate.models import SeverityLabel


def finding_score(finding_type: str, confidence: str, cfg: SeverityConfig) -> float:
    """base[type] * weight[confidence]."""
    return cfg.base[finding_type] * float(getattr(cfg.weight, confidence))


def incident_score(
    finding_scores: Collection[float],
    distinct_types: int,
    linked: bool,
    cfg: SeverityConfig,
) -> tuple[float, dict[str, float]]:
    """max(finding score) + extra_type_bonus per additional type + link_bonus, capped."""
    top = max(finding_scores)
    type_bonus = cfg.extra_type_bonus * max(0, distinct_types - 1)
    link_bonus = cfg.link_bonus if linked else 0.0
    total = min(cfg.cap, top + type_bonus + link_bonus)
    return round(total, 4), {
        "max_finding_score": top,
        "type_bonus": type_bonus,
        "link_bonus": link_bonus,
    }


def label(score: float, cfg: SeverityConfig) -> SeverityLabel:
    if score < cfg.buckets.low:
        return "low"
    if score < cfg.buckets.medium:
        return "medium"
    if score < cfg.buckets.high:
        return "high"
    return "critical"
