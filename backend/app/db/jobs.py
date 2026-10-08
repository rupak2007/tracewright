"""Job queue on PostgreSQL (`FOR UPDATE SKIP LOCKED`), lease and heartbeat (architecture §4, §21).

A claimed job holds a lease; the worker extends it while it works. A job whose lease expired belongs
to a crashed worker: it is requeued once, and failed the second time (`MAX_ATTEMPTS`), so a capture
that kills the worker cannot loop forever. Every function takes an open Session and flushes; the
caller commits, so a claim and its status change are one transaction.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Investigation, Job, WorkerHeartbeat

LEASE_S = 30 * 60
MAX_ATTEMPTS = 2
HEARTBEAT_S = 15
ACTIVE_WORKER_S = 45  # a heartbeat younger than this means a worker is alive


def _now() -> datetime:
    return datetime.now(UTC)


def enqueue(
    session: Session, investigation_id: str, job_type: str, params: dict[str, Any] | None = None
) -> Job:
    job = Job(
        investigation_id=investigation_id, type=job_type, status="queued", params=params or {}
    )
    session.add(job)
    session.flush()
    return job


def fail_expired(session: Session, now: datetime | None = None) -> list[Job]:
    """Requeue running jobs whose lease ran out; fail those that already had MAX_ATTEMPTS."""
    now = now or _now()
    expired = session.scalars(
        select(Job)
        .where(Job.status == "running", Job.lease_until < now)
        .with_for_update(skip_locked=True)
    ).all()
    failed: list[Job] = []
    for job in expired:
        if job.attempts >= MAX_ATTEMPTS:
            mark_failed(
                session, job, "the worker lease expired twice (worker crashed or hung)", now
            )
            failed.append(job)
        else:
            job.status = "queued"
            job.lease_until = None
    session.flush()
    return failed


def claim(
    session: Session,
    now: datetime | None = None,
    lease_s: int = LEASE_S,
    worker_id: str | None = None,
) -> Job | None:
    """Take the oldest queued job (other workers skip rows this one has locked)."""
    now = now or _now()
    fail_expired(session, now)
    job = session.scalars(
        select(Job)
        .where(Job.status == "queued")
        .order_by(Job.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    ).first()
    if job is None:
        return None
    job.status = "running"
    job.attempts += 1
    job.worker_id = worker_id
    job.lease_until = now + timedelta(seconds=lease_s)
    session.flush()
    return job


def running_for(session: Session, worker_id: str) -> list[Job]:
    return list(
        session.scalars(select(Job).where(Job.status == "running", Job.worker_id == worker_id))
    )


def extend_lease(
    session: Session, job: Job, now: datetime | None = None, lease_s: int = LEASE_S
) -> None:
    job.lease_until = (now or _now()) + timedelta(seconds=lease_s)
    session.flush()


def mark_done(session: Session, job: Job, now: datetime | None = None) -> None:
    job.status = "done"
    job.lease_until = None
    job.finished_at = now or _now()
    session.flush()


def mark_failed(session: Session, job: Job, error: str, now: datetime | None = None) -> None:
    job.status = "failed"
    job.error = error[:2000]
    job.lease_until = None
    job.finished_at = now or _now()
    if job.type == "analyze":
        inv = session.get(Investigation, job.investigation_id)
        if inv is not None and inv.status in ("queued", "running"):
            inv.status = "failed"
            inv.error_code = "WORKER_FAILED"
            inv.error_message = error[:500]
    session.flush()


def beat(session: Session, worker_id: str, now: datetime | None = None) -> None:
    row = session.get(WorkerHeartbeat, worker_id)
    if row is None:
        session.add(WorkerHeartbeat(worker_id=worker_id, beat_at=now or _now()))
    else:
        row.beat_at = now or _now()
    session.flush()


def worker_alive(session: Session, now: datetime | None = None) -> bool:
    now = now or _now()
    latest = session.scalars(
        select(WorkerHeartbeat.beat_at).order_by(WorkerHeartbeat.beat_at.desc()).limit(1)
    ).first()
    return latest is not None and now - latest <= timedelta(seconds=ACTIVE_WORKER_S)
