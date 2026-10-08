"""Response and request models of the HTTP API (also the source of the generated OpenAPI schema)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

FeedbackLabel = Literal["true_positive", "false_positive", "expected_benign"]


class UploadAccepted(BaseModel):
    id: str
    status: str


class InvestigationSummary(BaseModel):
    id: str
    original_name: str
    sha256: str
    size_bytes: int
    status: str
    stage: str
    error_code: str | None
    error_message: str | None
    created_at: datetime
    incident_count: int


class InvestigationDetail(InvestigationSummary):
    profile: dict[str, Any] | None
    warnings: list[Any] | None
    manifest: dict[str, Any] | None
    stage_ms: dict[str, Any] | None


class LinkOut(BaseModel):
    type: str
    from_incident: int
    to_incident: int
    from_local: str
    to_local: str
    reason: str


class IncidentSummary(BaseModel):
    id: int
    local_id: str
    rank: int
    primary_entity: str
    start_ts: datetime
    end_ts: datetime
    severity_score: float
    severity_label: str
    types: list[str]
    finding_count: int
    links: list[LinkOut]


class TechniqueOut(BaseModel):
    technique_id: str
    phrase: str


class FeedbackOut(BaseModel):
    id: int
    finding_id: int
    label: FeedbackLabel
    note: str
    created_at: datetime


class FindingOut(BaseModel):
    id: int
    local_id: str
    type: str
    detector_id: str
    detector_version: str
    primary_entity: str
    secondary_entities: list[Any]
    start_ts: datetime
    end_ts: datetime
    metrics: dict[str, Any]
    thresholds: dict[str, Any]
    confidence: str
    severity_score: float
    benign_causes: list[Any]
    evidence_total: int
    techniques: list[TechniqueOut]
    feedback: list[FeedbackOut]


class IncidentDetailOut(IncidentSummary):
    summary: str
    findings: list[FindingOut]
    cards: list[dict[str, Any]]
    playbooks: list[str]


class EvidenceOut(BaseModel):
    local_id: str
    kind: str
    finding_id: int
    zeek_uid: str | None
    ts: datetime | None
    fields: dict[str, Any]


class EvidencePage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[EvidenceOut]


class AnomaliesOut(BaseModel):
    summary: dict[str, Any]
    scored_windows: list[dict[str, Any]]
    promoted_findings: list[FindingOut]


class SliceAccepted(BaseModel):
    slice_id: int
    status: str


class SliceOut(BaseModel):
    id: int
    finding_id: int
    status: str
    size_bytes: int | None
    packets: int | None
    error: str | None
    created_at: datetime


class FeedbackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: FeedbackLabel
    note: str = Field(default="", max_length=2000)


class NetworkOut(BaseModel):
    internal_cidrs: list[str]
    known_hosts: dict[str, list[str]]
    allowlist: dict[str, Any]


class WorkerHealth(BaseModel):
    status: Literal["ok", "idle"]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    db: Literal["ok"]
    worker: Literal["alive", "unknown"]
