"""Run one queued job: `analyze` (the pipeline, then persist) or `slice` (cut a packet slice).

The worker is the only process that reads capture bytes. Both job types write their results into
the database (analysis rows / the slice row) and the artifacts volume; the API serves from there.
NFR-03: a failed analysis leaves no incidents behind, only its failure reason.
"""

import logging
import shutil
from pathlib import Path

import pandas as pd
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import IngestError, TracewrightError
from app.core.logging import log_context
from app.correlate.config import SeverityConfig
from app.db import jobs
from app.db.models import Finding, Investigation, Job, SliceRow
from app.db.persist import clear_results, persist_analysis, persist_failure
from app.slice.builder import SliceTooBroad, build_bpf, normalise_flows
from app.slice.runner import build_slice
from app.worker.pipeline import analyze_capture

logger = logging.getLogger(__name__)


def run_analyze(session: Session, settings: Settings, job: Job, severity: SeverityConfig) -> None:
    inv = session.get(Investigation, job.investigation_id)
    if inv is None:
        jobs.mark_failed(session, job, "the investigation no longer exists")
        return
    inv.status, inv.stage = "running", "validate"
    session.commit()
    out_dir = settings.artifacts_dir / inv.id
    if out_dir.exists():  # a requeued job: our own half-written artifacts, never an upload
        shutil.rmtree(out_dir)
    clear_results(session, inv.id)
    status = analyze_capture(settings.uploads_dir / inv.upload_name, out_dir, settings)
    if status.status == "completed":
        persist_analysis(session, inv, out_dir, severity)
        jobs.mark_done(session, job)
    else:
        persist_failure(session, inv, status)
        jobs.mark_done(session, job)  # the job ran; the investigation records why it failed
    session.commit()


def _flows_for(finding: Finding, conn_path: Path) -> list[tuple[str, str, object, str, object]]:
    conn = pd.read_parquet(
        conn_path, columns=["uid", "proto", "orig_h", "orig_p", "resp_h", "resp_p"]
    )
    rows = conn[conn["uid"].isin(finding.evidence_refs)]
    return [
        (str(r.proto), str(r.orig_h), r.orig_p, str(r.resp_h), r.resp_p)
        for r in rows.itertuples(index=False)
    ]


def run_slice(session: Session, settings: Settings, job: Job) -> None:
    slice_id = int(job.params["slice_id"])
    row = session.get(SliceRow, slice_id)
    if row is None:
        jobs.mark_failed(session, job, "the slice no longer exists")
        return
    row.status = "running"
    session.commit()
    finding = session.get(Finding, row.finding_id)
    inv = session.get(Investigation, job.investigation_id)
    try:
        if finding is None or inv is None:
            raise IngestError("SLICE_FAILED", "The finding no longer exists.")
        conn_path = settings.artifacts_dir / inv.id / "tables" / "conn.parquet"
        bpf = build_bpf(normalise_flows(_flows_for(finding, conn_path)))
        row.bpf = bpf
        result = build_slice(
            settings.uploads_dir / inv.upload_name,
            settings.artifacts_dir / inv.id / "slices" / f"{row.id}.pcap",
            bpf,
            finding.start_ts,
            finding.end_ts,
            tcpdump_bin=settings.tcpdump_bin,
            editcap_bin=settings.editcap_bin,
            capinfos_bin=settings.capinfos_bin,
            timeout_s=settings.tool_timeout_s * 2,
        )
        row.status, row.filename = "done", result.path.name
        row.size_bytes, row.packets, row.error = result.size_bytes, result.packets, None
    except SliceTooBroad as exc:
        row.status, row.error = "failed", f"SLICE_TOO_BROAD: {exc}"
    except TracewrightError as exc:
        row.status, row.error = "failed", f"{exc.code}: {exc.message}"
    jobs.mark_done(session, job)
    session.commit()


def process(session: Session, settings: Settings, job: Job, severity: SeverityConfig) -> None:
    """Dispatch by job type; an unexpected exception fails the job (and its investigation)."""
    with log_context(investigation_id=job.investigation_id, job_id=str(job.id)):
        try:
            if job.type == "analyze":
                run_analyze(session, settings, job, severity)
            elif job.type == "slice":
                run_slice(session, settings, job)
            else:
                jobs.mark_failed(session, job, f"unknown job type {job.type!r}")
                session.commit()
        except Exception as exc:
            session.rollback()
            logger.exception("job crashed")
            fresh = session.get(Job, job.id)
            if fresh is not None:
                jobs.mark_failed(session, fresh, f"Unexpected {type(exc).__name__}")
                session.commit()
