"""Incident and link records produced by correlation (architecture §9, §15)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

LinkType = Literal["TARGET_LATER_ACTIVE", "SHARED_EXTERNAL_PEER", "SAME_ACTOR_LATER"]
SeverityLabel = Literal["low", "medium", "high", "critical"]


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str  # "I-<n>", numbered after deterministic ordering
    primary_entity: str
    start_ts: datetime
    end_ts: datetime
    finding_ids: list[str]
    types: list[str]  # distinct finding types, sorted
    severity_score: float
    severity_label: SeverityLabel
    severity_breakdown: dict[str, float]  # max finding score, type bonus, link bonus


class Link(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: LinkType
    from_incident: str
    to_incident: str
    reason: str
    finding_ids: list[str]  # the findings that justify the link
