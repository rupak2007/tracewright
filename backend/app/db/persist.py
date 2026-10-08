"""Write an analysis (the artifacts of `analyze_capture`) into the database, and delete it again.

The API only ever reads these rows (architecture §4). Everything is stored exactly as the pipeline
produced it: findings keep their metrics, thresholds and evidence references; incidents keep the
full `IncidentDetail` JSON so reports render identically from the database and from the files.
"""

import json
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.correlate.severity import finding_score
from app.db.models import (
    AnomalyScoreRow,
    EvidenceRecord,
    Feedback,
    Finding,
    Incident,
    IncidentLink,
    Investigation,
    Job,
    Narrative,
    SliceRow,
    TechniqueRefRow,
)
from app.report.model import AnalysisOutput
from app.worker.pipeline import AnalysisStatus

ANOMALY_SCORER_FALLBACK = "off"


def clear_results(session: Session, investigation_id: str) -> None:
    """Remove derived rows of an investigation (used before re-persisting and by deletion)."""
    inc_ids = list(
        session.scalars(select(Incident.id).where(Incident.investigation_id == investigation_id))
    )
    f_ids = list(
        session.scalars(select(Finding.id).where(Finding.investigation_id == investigation_id))
    )
    if f_ids:
        session.execute(delete(Feedback).where(Feedback.finding_id.in_(f_ids)))
        session.execute(delete(SliceRow).where(SliceRow.finding_id.in_(f_ids)))
        session.execute(delete(TechniqueRefRow).where(TechniqueRefRow.finding_id.in_(f_ids)))
    if inc_ids:
        session.execute(delete(Narrative).where(Narrative.incident_id.in_(inc_ids)))
        session.execute(delete(EvidenceRecord).where(EvidenceRecord.incident_id.in_(inc_ids)))
    session.execute(delete(IncidentLink).where(IncidentLink.investigation_id == investigation_id))
    session.execute(delete(Finding).where(Finding.investigation_id == investigation_id))
    session.execute(delete(Incident).where(Incident.investigation_id == investigation_id))
    session.execute(
        delete(AnomalyScoreRow).where(AnomalyScoreRow.investigation_id == investigation_id)
    )
    session.flush()


def persist_failure(session: Session, inv: Investigation, status: AnalysisStatus) -> None:
    inv.status = "failed"
    inv.stage = status.stage
    inv.error_code = status.error_code
    inv.error_message = status.error_message
    inv.stage_ms = dict(status.stage_ms)
    session.flush()


def persist_analysis(
    session: Session, inv: Investigation, out_dir: Path, cfg_severity: Any
) -> None:
    """Load `incidents.json`, `profile.json`, `manifest.json`, `anomalies.json` from `out_dir`."""
    analysis = AnalysisOutput.model_validate_json((out_dir / "incidents.json").read_text("utf-8"))
    profile = json.loads((out_dir / "profile.json").read_text("utf-8"))
    manifest = json.loads((out_dir / "manifest.json").read_text("utf-8"))
    status = json.loads((out_dir / "status.json").read_text("utf-8"))
    anomalies = json.loads((out_dir / "anomalies.json").read_text("utf-8"))

    clear_results(session, inv.id)
    inc_pk: dict[str, int] = {}
    finding_pk: dict[str, int] = {}
    for rank, detail in enumerate(analysis.incidents, start=1):
        inc = detail.incident
        row = Incident(
            investigation_id=inv.id,
            local_id=inc.id,
            rank=rank,
            primary_entity=inc.primary_entity,
            start_ts=inc.start_ts,
            end_ts=inc.end_ts,
            severity_score=inc.severity_score,
            severity_label=inc.severity_label,
            template_summary=detail.summary,
            detail=json.loads(detail.model_dump_json()),
        )
        session.add(row)
        session.flush()
        inc_pk[inc.id] = row.id
        for f in detail.findings:
            frow = Finding(
                investigation_id=inv.id,
                incident_id=row.id,
                local_id=f.id,
                type=f.type,
                detector_id=f.detector_id,
                detector_version=f.detector_version,
                primary_entity=f.primary_entity,
                secondary_entities=list(f.secondary_entities),
                start_ts=f.start_ts,
                end_ts=f.end_ts,
                metrics=dict(f.metrics),
                thresholds=dict(f.thresholds),
                confidence=f.confidence,
                severity_score=finding_score(f.type, f.confidence, cfg_severity),
                benign_causes=list(f.benign_causes),
                evidence_refs=list(f.evidence_refs),
                evidence_total=f.evidence_count,
                suppressed=f.suppressed_by_allowlist,
            )
            session.add(frow)
            session.flush()
            finding_pk[f.id] = frow.id
            for ref in detail.techniques.get(f.id, []):
                session.add(
                    TechniqueRefRow(
                        finding_id=frow.id, technique_id=ref.technique_id, phrase=ref.phrase
                    )
                )
        for seq, item in enumerate(detail.evidence):
            session.add(
                EvidenceRecord(
                    incident_id=row.id,
                    finding_id=finding_pk[item.finding_id],
                    local_id=item.local_id,
                    seq=seq,
                    kind=item.kind,
                    zeek_uid=item.zeek_uid,
                    ts=item.ts,
                    fields=dict(item.fields),
                )
            )
    for link in analysis.links:
        session.add(
            IncidentLink(
                investigation_id=inv.id,
                from_incident=inc_pk[link.from_incident],
                to_incident=inc_pk[link.to_incident],
                type=link.type,
                reason=link.reason,
            )
        )
    for w in anomalies.get("scored_windows", []):
        session.add(
            AnomalyScoreRow(
                investigation_id=inv.id,
                host=w["host"],
                window_start=_parse(w["window_start"]),
                scorer=anomalies.get("scorer", ANOMALY_SCORER_FALLBACK),
                score=w["score"],
                rank=w["rank"],
                rule_explained=w["rule_explained"],
                top_features=w["top_features"],
            )
        )
    inv.status = "completed"
    inv.stage = "explain"
    inv.error_code = inv.error_message = None
    inv.profile = {
        **profile,
        "anomalies": {k: v for k, v in anomalies.items() if k != "scored_windows"},
    }
    inv.warnings = profile.get("warnings", [])
    inv.manifest = manifest
    inv.stage_ms = status.get("stage_ms", {})
    session.flush()


def _parse(value: str) -> Any:
    from datetime import datetime

    return datetime.fromisoformat(value)


def delete_investigation(
    session: Session, investigation_id: str, uploads_dir: Path, artifacts_dir: Path
) -> bool:
    """FR-45: rows (all derived data, jobs, the investigation) and both file trees are removed."""
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        return False
    clear_results(session, investigation_id)
    session.execute(delete(Job).where(Job.investigation_id == investigation_id))
    upload = uploads_dir / inv.upload_name
    session.delete(inv)
    session.flush()
    upload.unlink(missing_ok=True)
    shutil.rmtree(artifacts_dir / investigation_id, ignore_errors=True)
    return True
