"""Job queue, lease/requeue and heartbeat (architecture §21). SQLite stands in for PostgreSQL, so
`SKIP LOCKED` itself is a PostgreSQL behaviour that these tests cannot exercise."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.db import jobs
from app.db.models import Investigation, Job
from app.db.persist import delete_investigation
from tests.db_helpers import make_engine

T0 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)


@pytest.fixture
def session() -> Iterator[Session]:
    with Session(make_engine()) as s:
        s.add(
            Investigation(
                id="inv1", upload_name="inv1.pcap", sha256="ab" * 32, size_bytes=1, status="queued"
            )
        )
        s.commit()
        yield s


def test_claim_is_fifo_sets_a_lease_and_counts_the_attempt(session: Session) -> None:
    a = jobs.enqueue(session, "inv1", "analyze")
    b = jobs.enqueue(session, "inv1", "slice", {"slice_id": 1})
    first = jobs.claim(session, now=T0, lease_s=60, worker_id="w1")
    assert first is not None and first.id == a.id and first.status == "running"
    assert first.attempts == 1 and first.worker_id == "w1"
    assert first.lease_until == T0 + timedelta(seconds=60)
    second = jobs.claim(session, now=T0, worker_id="w2")
    assert second is not None and second.id == b.id
    assert jobs.claim(session, now=T0) is None  # nothing queued; running jobs are not handed out


def test_an_expired_lease_requeues_once_then_fails_the_job_and_its_investigation(
    session: Session,
) -> None:
    job = jobs.enqueue(session, "inv1", "analyze")
    jobs.claim(session, now=T0, lease_s=60)
    later = T0 + timedelta(seconds=61)
    again = jobs.claim(session, now=later, lease_s=60)  # lease expired: requeued, claimed again
    assert again is not None and again.id == job.id and again.attempts == 2
    assert jobs.claim(session, now=later) is None
    final = later + timedelta(seconds=61)
    assert jobs.claim(session, now=final) is None  # second expiry: not requeued a second time
    session.refresh(job)
    assert job.status == "failed" and "lease expired twice" in (job.error or "")
    inv = session.get(Investigation, "inv1")
    assert inv is not None and inv.status == "failed" and inv.error_code == "WORKER_FAILED"


def test_a_live_lease_is_not_taken_over(session: Session) -> None:
    jobs.enqueue(session, "inv1", "analyze")
    jobs.claim(session, now=T0, lease_s=60)
    assert jobs.claim(session, now=T0 + timedelta(seconds=59)) is None
    assert jobs.fail_expired(session, now=T0 + timedelta(seconds=59)) == []


def test_extending_the_lease_keeps_a_slow_job_alive(session: Session) -> None:
    job = jobs.enqueue(session, "inv1", "analyze")
    claimed = jobs.claim(session, now=T0, lease_s=60, worker_id="w1")
    assert claimed is not None
    jobs.extend_lease(session, claimed, now=T0 + timedelta(seconds=50), lease_s=60)
    assert jobs.claim(session, now=T0 + timedelta(seconds=100)) is None  # would have expired at 60
    assert [j.id for j in jobs.running_for(session, "w1")] == [job.id]
    assert jobs.running_for(session, "someone-else") == []


def test_done_and_failed_jobs_are_final_and_slice_failures_leave_the_investigation(
    session: Session,
) -> None:
    done = jobs.enqueue(session, "inv1", "analyze")
    jobs.mark_done(session, done, now=T0)
    assert done.status == "done" and done.finished_at == T0 and done.lease_until is None
    sl = jobs.enqueue(session, "inv1", "slice", {"slice_id": 1})
    jobs.mark_failed(session, sl, "boom " * 1000, now=T0)
    assert sl.status == "failed" and len(sl.error or "") == 2000
    inv = session.get(Investigation, "inv1")
    assert (
        inv is not None and inv.status == "queued"
    )  # only analyze failures fail the investigation
    assert jobs.claim(session, now=T0) is None


def test_worker_heartbeat_and_liveness_window(session: Session) -> None:
    assert not jobs.worker_alive(session, now=T0)
    jobs.beat(session, "w1", now=T0)
    jobs.beat(session, "w1", now=T0 + timedelta(seconds=10))  # updates the same row
    assert jobs.worker_alive(session, now=T0 + timedelta(seconds=40))
    assert not jobs.worker_alive(session, now=T0 + timedelta(seconds=10 + jobs.ACTIVE_WORKER_S + 1))


def test_deleting_an_unknown_investigation_is_a_no_op(session: Session, tmp_path: Path) -> None:
    assert delete_investigation(session, "nope", tmp_path, tmp_path) is False
    session.add(Job(investigation_id="inv1", type="analyze"))
    session.commit()
    assert delete_investigation(session, "inv1", tmp_path, tmp_path) is True
    session.commit()
    assert session.get(Investigation, "inv1") is None
