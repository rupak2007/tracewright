"""Investigation endpoints: upload, list, read, delete, ranked incidents and anomaly list."""

from fastapi import APIRouter, Request, Response
from sqlalchemy import func, select

from app.api.deps import AuthDep, SessionDep, SettingsDep
from app.api.errors import ApiError
from app.api.schemas import (
    AnomaliesOut,
    IncidentSummary,
    InvestigationDetail,
    InvestigationSummary,
    UploadAccepted,
)
from app.api.serialize import finding_out, incident_summary, links_for
from app.api.upload import receive_capture
from app.db import jobs
from app.db.models import AnomalyScoreRow, Finding, Incident, Investigation
from app.db.persist import delete_investigation

router = APIRouter(dependencies=[AuthDep])


def _incident_count(session: SessionDep, investigation_id: str) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.investigation_id == investigation_id)
        )
        or 0
    )


def _summary(session: SessionDep, inv: Investigation) -> InvestigationSummary:
    return InvestigationSummary(
        id=inv.id,
        original_name=inv.original_name,
        sha256=inv.sha256,
        size_bytes=inv.size_bytes,
        status=inv.status,
        stage=inv.stage,
        error_code=inv.error_code,
        error_message=inv.error_message,
        created_at=inv.created_at,
        incident_count=_incident_count(session, inv.id),
    )


def _get(session: SessionDep, investigation_id: str) -> Investigation:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise ApiError(404, "NOT_FOUND", "No such investigation.")
    return inv


@router.post("/investigations", status_code=202, response_model=UploadAccepted)
async def create_investigation(
    request: Request, session: SessionDep, settings: SettingsDep
) -> UploadAccepted:
    stored = await receive_capture(request, settings)
    try:
        inv = Investigation(
            id=str(stored.capture_id),
            original_name=stored.original_name,
            upload_name=stored.path.name,
            sha256=stored.info.sha256,
            size_bytes=stored.info.size_bytes,
            status="queued",
            stage="queued",
        )
        session.add(inv)
        session.flush()
        jobs.enqueue(session, inv.id, "analyze")
        session.commit()
    except BaseException:
        session.rollback()
        stored.path.unlink(missing_ok=True)
        raise
    return UploadAccepted(id=inv.id, status=inv.status)


@router.get("/investigations", response_model=list[InvestigationSummary])
def list_investigations(session: SessionDep) -> list[InvestigationSummary]:
    rows = session.scalars(select(Investigation).order_by(Investigation.created_at.desc())).all()
    return [_summary(session, inv) for inv in rows]


@router.get("/investigations/{investigation_id}", response_model=InvestigationDetail)
def get_investigation(investigation_id: str, session: SessionDep) -> InvestigationDetail:
    inv = _get(session, investigation_id)
    return InvestigationDetail(
        **_summary(session, inv).model_dump(),
        profile=inv.profile,
        warnings=inv.warnings,
        manifest=inv.manifest,
        stage_ms=inv.stage_ms,
    )


@router.delete("/investigations/{investigation_id}", status_code=204)
def remove_investigation(
    investigation_id: str, session: SessionDep, settings: SettingsDep
) -> Response:
    inv = _get(session, investigation_id)
    if inv.status == "running":
        raise ApiError(409, "CONFLICT", "The analysis is running; delete it when it has finished.")
    delete_investigation(session, investigation_id, settings.uploads_dir, settings.artifacts_dir)
    session.commit()
    return Response(status_code=204)


@router.get("/investigations/{investigation_id}/incidents", response_model=list[IncidentSummary])
def list_incidents(investigation_id: str, session: SessionDep) -> list[IncidentSummary]:
    _get(session, investigation_id)
    rows = session.scalars(
        select(Incident)
        .where(Incident.investigation_id == investigation_id)
        .order_by(Incident.rank)
    ).all()
    return [
        incident_summary(session, inc, links_for(session, inc.investigation_id)) for inc in rows
    ]


@router.get("/investigations/{investigation_id}/anomalies", response_model=AnomaliesOut)
def list_anomalies(investigation_id: str, session: SessionDep) -> AnomaliesOut:
    inv = _get(session, investigation_id)
    windows = session.scalars(
        select(AnomalyScoreRow)
        .where(AnomalyScoreRow.investigation_id == investigation_id)
        .order_by(AnomalyScoreRow.rank)
        .limit(50)
    ).all()
    promoted = session.scalars(
        select(Finding)
        .where(Finding.investigation_id == investigation_id, Finding.type == "UNEXPLAINED_ANOMALY")
        .order_by(Finding.id)
    ).all()
    summary = (inv.profile or {}).get("anomalies", {})
    return AnomaliesOut(
        summary={**summary, "label": "unusual relative to this capture; not necessarily malicious"},
        scored_windows=[
            {
                "host": w.host,
                "window_start": w.window_start.isoformat(),
                "score": w.score,
                "rank": w.rank,
                "rule_explained": w.rule_explained,
                "top_features": w.top_features,
            }
            for w in windows
        ],
        promoted_findings=[finding_out(session, f) for f in promoted],
    )
