"""The analysis result for one capture: what `incidents.json`, the report and the API serve."""

from pydantic import BaseModel, ConfigDict

from app.attack.cards import Card
from app.attack.mapping import TechniqueRef
from app.correlate.models import Incident, Link
from app.detect.base import Finding
from app.explain.evidence_ids import EvidenceItem


class IncidentDetail(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    incident: Incident
    findings: list[Finding]
    techniques: dict[str, list[TechniqueRef]]  # finding id -> techniques it is consistent with
    cards: list[Card]  # technique cards (K-T...) for the techniques above, unique, sorted
    playbooks: list[str]  # K-PB-DET-... ids that apply to the finding types
    evidence: list[EvidenceItem]
    summary: str  # template summary; every sentence cites E-ids
    links: list[Link]  # links where this incident is either end


class AnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    investigation_id: str
    capture_sha256: str
    attack_version: str
    incidents: list[IncidentDetail]  # ranked: severity score descending, then start time
    links: list[Link]
    suppressed: dict[str, dict[str, int]]
