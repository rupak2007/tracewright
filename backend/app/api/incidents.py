"""Incident, evidence, report, slice, feedback and configuration endpoints."""

from typing import Annotated, Literal

from fastapi import APIRouter, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy import func, select

from app.api.deps import INT32_MAX, AuthDep, RowId, SessionDep, SettingsDep
from app.api.errors import ApiError
from app.api.narratives import validated_narrative_block
from app.api.schemas import (
    EvidencePage,
    FeedbackIn,
    FeedbackOut,
    IncidentDetailOut,
    NetworkOut,
    SliceAccepted,
    SliceOut,
)
from app.api.serialize import evidence_out, feedback_out, incident_detail, links_for
from app.db import jobs
from app.db.models import (
    EvidenceRecord,
    Feedback,
    Finding,
    Incident,
    Investigation,
    SliceRow,
)
from app.profile.context import load_network_context
from app.profile.profile import CaptureProfile
from app.report.html import render_html
from app.report.model import AnalysisOutput, IncidentDetail
from app.report.render import render_markdown

router = APIRouter(dependencies=[AuthDep])


def _incident(session: SessionDep, incident_id: int) -> Incident:
    inc = session.get(Incident, incident_id)
    if inc is None:
        raise ApiError(404, "NOT_FOUND", "No such incident.")
    return inc


def _finding(session: SessionDep, finding_id: int) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise ApiError(404, "NOT_FOUND", "No such finding.")
    return finding


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
def get_incident(incident_id: RowId, session: SessionDep) -> IncidentDetailOut:
    inc = _incident(session, incident_id)
    return incident_detail(session, inc, links_for(session, inc.investigation_id))


@router.get("/incidents/{incident_id}/evidence", response_model=EvidencePage)
def get_evidence(
    incident_id: RowId,
    session: SessionDep,
    finding_id: Annotated[int | None, Query(ge=1, le=INT32_MAX)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=INT32_MAX)] = 0,
) -> EvidencePage:
    _incident(session, incident_id)
    query = select(EvidenceRecord).where(EvidenceRecord.incident_id == incident_id)
    if finding_id is not None:
        query = query.where(EvidenceRecord.finding_id == finding_id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(EvidenceRecord.seq).limit(limit).offset(offset)).all()
    return EvidencePage(
        total=int(total), limit=limit, offset=offset, items=[evidence_out(r) for r in rows]
    )


@router.get("/incidents/{incident_id}/report")
def get_report(
    incident_id: RowId,
    session: SessionDep,
    settings: SettingsDep,
    format: Literal["md", "html"] = "md",
) -> Response:
    inc = _incident(session, incident_id)
    inv = session.get(Investigation, inc.investigation_id)
    if inv is None or inv.profile is None or inv.manifest is None:
        raise ApiError(409, "CONFLICT", "The investigation has no completed analysis.")
    detail = IncidentDetail.model_validate(inc.detail)
    analysis = AnalysisOutput(
        investigation_id=inv.id,
        capture_sha256=inv.sha256,
        attack_version=str(inv.manifest.get("attack_version", "")),
        incidents=[detail],
        links=detail.links,
        suppressed=inv.profile.get("suppressed_findings", {}),
    )
    profile = CaptureProfile.model_validate(inv.profile)
    pairs = session.execute(
        select(Finding.local_id, Feedback.label, Feedback.note)
        .join(Feedback, Feedback.finding_id == Finding.id)
        .where(Finding.incident_id == inc.id)
        .order_by(Feedback.id)
    ).all()
    feedback: dict[str, list[tuple[str, str]]] = {}
    for local_id, label, note in pairs:
        feedback.setdefault(local_id, []).append((label, note))
    narratives = validated_narrative_block(session, inc, inv, settings)
    title = f"Tracewright incident report {inc.local_id}"
    if format == "html":
        body = render_html(analysis, profile, title, inv.manifest, feedback, narratives)
        media = "text/html; charset=utf-8"
    else:
        body = render_markdown(analysis, profile, title, inv.manifest, feedback, narratives)
        media = "text/markdown; charset=utf-8"
    name = f"tracewright-{inc.local_id}.{format}"
    return Response(
        body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/findings/{finding_id}/slice", status_code=202, response_model=SliceAccepted)
def create_slice(finding_id: RowId, session: SessionDep) -> SliceAccepted:
    finding = _finding(session, finding_id)
    inv = session.get(Investigation, finding.investigation_id)
    if inv is None or inv.status != "completed":
        raise ApiError(409, "CONFLICT", "The investigation has no completed analysis.")
    existing = session.scalars(
        select(SliceRow)
        .where(
            SliceRow.finding_id == finding_id, SliceRow.status.in_(("queued", "running", "done"))
        )
        .order_by(SliceRow.id.desc())
    ).first()
    if existing is not None:
        return SliceAccepted(slice_id=existing.id, status=existing.status)
    row = SliceRow(finding_id=finding_id, status="queued")
    session.add(row)
    session.flush()
    jobs.enqueue(session, inv.id, "slice", {"slice_id": row.id})
    session.commit()
    return SliceAccepted(slice_id=row.id, status=row.status)


def _slice(session: SessionDep, slice_id: int) -> SliceRow:
    row = session.get(SliceRow, slice_id)
    if row is None:
        raise ApiError(404, "NOT_FOUND", "No such slice.")
    return row


@router.get("/slices/{slice_id}", response_model=SliceOut)
def get_slice(slice_id: RowId, session: SessionDep) -> SliceOut:
    row = _slice(session, slice_id)
    return SliceOut(
        id=row.id,
        finding_id=row.finding_id,
        status=row.status,
        size_bytes=row.size_bytes,
        packets=row.packets,
        error=row.error,
        created_at=row.created_at,
    )


@router.get("/slices/{slice_id}/download")
def download_slice(slice_id: RowId, session: SessionDep, settings: SettingsDep) -> FileResponse:
    row = _slice(session, slice_id)
    finding = session.get(Finding, row.finding_id)
    if row.status != "done" or row.filename is None or finding is None:
        raise ApiError(409, "CONFLICT", "The slice is not ready.")
    path = settings.artifacts_dir / finding.investigation_id / "slices" / row.filename
    if not path.is_file():
        raise ApiError(404, "NOT_FOUND", "The slice file is missing.")
    return FileResponse(
        path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"tracewright-slice-{row.id}.pcap",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.post("/findings/{finding_id}/feedback", status_code=201, response_model=FeedbackOut)
def add_feedback(finding_id: RowId, body: FeedbackIn, session: SessionDep) -> FeedbackOut:
    _finding(session, finding_id)
    row = Feedback(finding_id=finding_id, label=body.label, note=body.note)
    session.add(row)
    session.commit()
    return feedback_out(row)


@router.get("/config/network", response_model=NetworkOut)
def get_network(settings: SettingsDep) -> NetworkOut:
    ctx = load_network_context(settings.config_dir / "network.yaml")
    return NetworkOut(
        internal_cidrs=[str(n) for n in ctx.internal_cidrs],
        known_hosts=ctx.known_hosts.model_dump(),
        allowlist=ctx.allowlist.model_dump(),
    )
