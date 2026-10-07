"""Correlation entry point (stage S6): findings -> incidents + links + severity. Pure."""

from collections.abc import Sequence
from dataclasses import dataclass

from app.correlate.config import CorrelationConfig
from app.correlate.incidents import group_findings
from app.correlate.links import IncidentRef, build_links
from app.correlate.models import Incident, Link
from app.correlate.severity import finding_score, incident_score, label
from app.detect.base import Finding


@dataclass(frozen=True)
class CorrelationResult:
    incidents: list[Incident]
    links: list[Link]
    exfil_with_beacon: frozenset[str]  # EXFIL finding ids that share a destination with a BEACON


def correlate(findings: Sequence[Finding], cfg: CorrelationConfig) -> CorrelationResult:
    by_id = {f.id: f for f in findings}
    groups = group_findings(findings, cfg.gap_s)
    refs = [
        IncidentRef(f"I-{n}", g.primary_entity, g.start_ts, g.finding_ids)
        for n, g in enumerate(groups, start=1)
    ]
    linked = build_links(refs, by_id)
    incidents: list[Incident] = []
    for ref, group in zip(refs, groups, strict=True):
        members = [by_id[fid] for fid in group.finding_ids]
        scores = [finding_score(f.type, f.confidence, cfg.severity) for f in members]
        types = sorted({f.type for f in members})
        is_linked = ref.id in linked.target_side or ref.id in linked.shared_peer_incidents
        score, breakdown = incident_score(scores, len(types), is_linked, cfg.severity)
        incidents.append(
            Incident(
                id=ref.id,
                primary_entity=group.primary_entity,
                start_ts=group.start_ts,
                end_ts=group.end_ts,
                finding_ids=list(group.finding_ids),
                types=types,
                severity_score=score,
                severity_label=label(score, cfg.severity),
                severity_breakdown=breakdown,
            )
        )
    return CorrelationResult(incidents, linked.links, frozenset(linked.exfil_with_beacon))
