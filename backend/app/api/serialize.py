"""Database rows -> API models."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import (
    EvidenceOut,
    FeedbackOut,
    FindingOut,
    IncidentDetailOut,
    IncidentSummary,
    LinkOut,
    TechniqueOut,
)
from app.db.models import (
    EvidenceRecord,
    Feedback,
    Finding,
    Incident,
    IncidentLink,
    TechniqueRefRow,
)


def links_for(session: Session, investigation_id: str) -> list[LinkOut]:
    locals_ = {
        i.id: i.local_id
        for i in session.scalars(
            select(Incident).where(Incident.investigation_id == investigation_id)
        )
    }
    rows = session.scalars(
        select(IncidentLink)
        .where(IncidentLink.investigation_id == investigation_id)
        .order_by(IncidentLink.type, IncidentLink.id)
    )
    return [
        LinkOut(
            type=r.type,
            from_incident=r.from_incident,
            to_incident=r.to_incident,
            from_local=locals_[r.from_incident],
            to_local=locals_[r.to_incident],
            reason=r.reason,
        )
        for r in rows
    ]


def incident_summary(session: Session, inc: Incident, all_links: list[LinkOut]) -> IncidentSummary:
    types = sorted({str(t) for t in inc.detail.get("incident", {}).get("types", [])})
    return IncidentSummary(
        id=inc.id,
        local_id=inc.local_id,
        rank=inc.rank,
        primary_entity=inc.primary_entity,
        start_ts=inc.start_ts,
        end_ts=inc.end_ts,
        severity_score=inc.severity_score,
        severity_label=inc.severity_label,
        types=types,
        finding_count=len(inc.detail.get("findings", [])),
        links=[lk for lk in all_links if inc.id in (lk.from_incident, lk.to_incident)],
    )


def feedback_out(row: Feedback) -> FeedbackOut:
    return FeedbackOut(
        id=row.id,
        finding_id=row.finding_id,
        label=row.label,
        note=row.note,
        created_at=row.created_at,
    )


def finding_out(session: Session, f: Finding) -> FindingOut:
    techniques = session.scalars(
        select(TechniqueRefRow)
        .where(TechniqueRefRow.finding_id == f.id)
        .order_by(TechniqueRefRow.id)
    )
    feedback = session.scalars(
        select(Feedback).where(Feedback.finding_id == f.id).order_by(Feedback.id)
    )
    return FindingOut(
        id=f.id,
        local_id=f.local_id,
        type=f.type,
        detector_id=f.detector_id,
        detector_version=f.detector_version,
        primary_entity=f.primary_entity,
        secondary_entities=f.secondary_entities,
        start_ts=f.start_ts,
        end_ts=f.end_ts,
        metrics=f.metrics,
        thresholds=f.thresholds,
        confidence=f.confidence,
        severity_score=f.severity_score,
        benign_causes=f.benign_causes,
        evidence_total=f.evidence_total,
        techniques=[TechniqueOut(technique_id=t.technique_id, phrase=t.phrase) for t in techniques],
        feedback=[feedback_out(fb) for fb in feedback],
    )


def incident_detail(session: Session, inc: Incident, all_links: list[LinkOut]) -> IncidentDetailOut:
    base = incident_summary(session, inc, all_links)
    findings = session.scalars(
        select(Finding).where(Finding.incident_id == inc.id).order_by(Finding.id)
    ).all()
    return IncidentDetailOut(
        **base.model_dump(),
        summary=inc.template_summary,
        findings=[finding_out(session, f) for f in findings],
        cards=list(inc.detail.get("cards", [])),
        playbooks=list(inc.detail.get("playbooks", [])),
    )


def evidence_out(row: EvidenceRecord) -> EvidenceOut:
    return EvidenceOut(
        local_id=row.local_id,
        kind=row.kind,
        finding_id=row.finding_id,
        zeek_uid=row.zeek_uid,
        ts=row.ts,
        fields=row.fields,
    )
