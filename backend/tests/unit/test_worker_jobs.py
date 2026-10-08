"""Worker jobs: analyze (persist, failure isolation, requeue) and slice (fake tcpdump/editcap)."""

from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db import jobs
from app.db.models import Finding, Incident, Job, SliceRow
from app.worker import jobs_runner
from app.worker.analysis_config import load_analysis_config
from tests.db_helpers import add_upload, app_settings, make_engine, seed_completed
from tests.helpers import capinfos_table, fake_executable

TCPDUMP = "\n".join(
    [
        "import sys, pathlib",
        "args = sys.argv[1:]",
        "out = pathlib.Path(args[args.index('-w') + 1])",
        "(out.parent / 'tcpdump.args').write_text(chr(10).join(args))",
        "out.write_bytes(open(args[args.index('-r') + 1], 'rb').read())",
        "",
    ]
)
EDITCAP = "\n".join(
    [
        "import sys, shutil, os, pathlib",
        "args = sys.argv[1:]",
        "note = os.environ.get('TZ', '') + chr(10) + chr(10).join(args)",
        "pathlib.Path(args[-1]).parent.joinpath('editcap.args').write_text(note)",
        "shutil.copyfile(args[-2], args[-1])",
        "",
    ]
)


def capinfos(packets: int) -> str:
    return f"import sys\nprint({capinfos_table(packets=str(packets), duration='5')!r}, end='')\n"


@pytest.fixture
def env(tmp_path: Path) -> tuple[Settings, Engine]:
    settings = app_settings(tmp_path)
    return settings, make_engine()


def run_next(session: Session, settings: Settings) -> Job:
    job = jobs.claim(session)
    assert job is not None
    session.commit()
    severity = load_analysis_config(settings).correlation.severity
    jobs_runner.process(session, settings, job, severity)
    session.refresh(job)
    return job


# ---- analyze ----------------------------------------------------------------------------
def test_an_analyze_job_runs_the_pipeline_and_persists_the_result(
    env: tuple[Settings, Engine],
) -> None:
    settings, engine = env
    with Session(engine) as s:
        inv = add_upload(s, settings)
        job = run_next(s, settings)
        s.refresh(inv)
        assert job.status == "done" and job.attempts == 1
        assert inv.status == "completed" and inv.stage == "explain" and inv.error_code is None
        assert (
            s.scalar(
                select(func.count())
                .select_from(Incident)
                .where(Incident.investigation_id == inv.id)
            )
            == 4
        )
        assert (settings.artifacts_dir / inv.id / "incidents.json").is_file()
        assert inv.manifest is not None and inv.manifest["counts"]["incidents"] == 4


def test_a_failed_analysis_leaves_no_incidents_only_its_reason(
    env: tuple[Settings, Engine],
) -> None:
    """NFR-03: no partial incident set may look complete."""
    settings, engine = env
    broken = settings.model_copy(
        update={
            "zeek_bin": fake_executable(
                settings.uploads_dir.parent, "zeek2", "import sys\nsys.exit(3)\n"
            )
        }
    )
    with Session(engine) as s:
        inv = add_upload(s, broken)
        job = run_next(s, broken)
        s.refresh(inv)
        assert job.status == "done"  # the job ran; the investigation records the failure
        assert inv.status == "failed" and inv.error_code and inv.stage == "zeek_parse"
        assert s.scalar(select(func.count()).select_from(Incident)) == 0


def test_a_requeued_analyze_job_starts_from_clean_artifacts(env: tuple[Settings, Engine]) -> None:
    settings, engine = env
    with Session(engine) as s:
        inv = add_upload(s, settings)
        stale = settings.artifacts_dir / inv.id
        stale.mkdir(parents=True)
        (stale / "half-written.json").write_text("{}")
        run_next(s, settings)
        assert not (stale / "half-written.json").exists() and (stale / "incidents.json").is_file()
        # re-running the same investigation replaces its rows instead of duplicating them
        s.add(Job(investigation_id=inv.id, type="analyze"))
        s.commit()
        run_next(s, settings)
        assert s.scalar(select(func.count()).select_from(Incident)) == 4


def test_a_crash_while_analysing_fails_the_job_and_the_investigation(
    env: tuple[Settings, Engine], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, engine = env

    def boom(*_: object, **__: object) -> None:
        raise MemoryError("out of memory")

    monkeypatch.setattr(jobs_runner, "analyze_capture", boom)
    with Session(engine) as s:
        inv = add_upload(s, settings)
        job = run_next(s, settings)
        s.refresh(inv)
        assert job.status == "failed" and "MemoryError" in (job.error or "")
        assert inv.status == "failed" and inv.error_code == "WORKER_FAILED"


def test_unknown_job_types_and_vanished_investigations_fail_cleanly(
    env: tuple[Settings, Engine],
) -> None:
    settings, engine = env
    with Session(engine) as s:
        inv = add_upload(s, settings)
        s.add(Job(investigation_id=inv.id, type="mystery"))
        s.commit()
        first = jobs.claim(s)
        assert first is not None and first.type == "analyze"  # FIFO: the real job is first
        first.status = "done"
        s.commit()
        mystery = run_next(s, settings)
        assert mystery.status == "failed" and "unknown job type" in (mystery.error or "")


# ---- slice ------------------------------------------------------------------------------
def slice_settings(base: Settings, tcpdump_body: str = TCPDUMP, packets: int = 3) -> Settings:
    folder = base.uploads_dir.parent
    return base.model_copy(
        update={
            "tcpdump_bin": fake_executable(folder, "tcpdump", tcpdump_body),
            "editcap_bin": fake_executable(folder, "editcap", EDITCAP),
            "capinfos_bin": fake_executable(folder, "capinfos", capinfos(packets)),
        }
    )


def queue_slice(s: Session, inv_id: str, finding_type: str) -> int:
    finding = s.scalars(
        select(Finding).where(Finding.investigation_id == inv_id, Finding.type == finding_type)
    ).first()
    assert finding is not None
    row = SliceRow(finding_id=finding.id, status="queued")
    s.add(row)
    s.flush()
    jobs.enqueue(s, inv_id, "slice", {"slice_id": row.id})
    s.commit()
    return row.id


def test_a_slice_job_builds_the_filter_from_the_findings_flows_and_writes_the_pcap(
    env: tuple[Settings, Engine],
) -> None:
    settings, engine = env
    with Session(engine) as s:
        inv_id = seed_completed(engine, settings)
        for existing in s.scalars(select(Job)):
            existing.status = "done"
        s.commit()
        slice_id = queue_slice(s, inv_id, "BRUTE")
        tools = slice_settings(settings)
        job = run_next(s, tools)
        row = s.get(SliceRow, slice_id)
        assert row is not None and job.status == "done"
        assert row.status == "done" and row.packets == 3 and row.filename == f"{slice_id}.pcap"
        out = settings.artifacts_dir / inv_id / "slices" / f"{slice_id}.pcap"
        assert out.is_file() and row.size_bytes == out.stat().st_size
        assert "host 10.0.0.66" in (row.bpf or "") and "host 10.0.1.21" in (row.bpf or "")
        assert "port 21" in (row.bpf or "") and ";" not in (row.bpf or "")
        argv = (out.parent / "tcpdump.args").read_text().splitlines()
        assert argv[:2] == ["-n", "-r"] and argv[-1] == row.bpf  # the filter is ONE argument
        editcap_args = (out.parent / "editcap.args").read_text().splitlines()
        assert editcap_args[0] == "UTC" and "-A" in editcap_args and "-B" in editcap_args


def test_slice_failures_are_reported_with_a_reason(env: tuple[Settings, Engine]) -> None:
    settings, engine = env
    with Session(engine) as s:
        inv_id = seed_completed(engine, settings)
        for existing in s.scalars(select(Job)):
            existing.status = "done"
        s.commit()
        failing = queue_slice(s, inv_id, "SCAN")
        run_next(s, slice_settings(settings, tcpdump_body="import sys\nsys.exit(2)\n"))
        row = s.get(SliceRow, failing)
        assert row is not None and row.status == "failed" and "SLICE_FAILED" in (row.error or "")
        empty = queue_slice(s, inv_id, "BRUTE")
        run_next(s, slice_settings(settings, packets=0))
        row = s.get(SliceRow, empty)
        assert row is not None and row.status == "failed" and "SLICE_EMPTY" in (row.error or "")
        assert not (settings.artifacts_dir / inv_id / "slices" / f"{empty}.pcap").exists()


def test_a_finding_without_connection_evidence_cannot_be_sliced(
    env: tuple[Settings, Engine],
) -> None:
    settings, engine = env
    with Session(engine) as s:
        inv_id = seed_completed(engine, settings)
        for existing in s.scalars(select(Job)):
            existing.status = "done"
        for f in s.scalars(select(Finding)):
            f.evidence_refs = []
        s.commit()
        slice_id = queue_slice(s, inv_id, "BRUTE")
        run_next(s, slice_settings(settings))
        row = s.get(SliceRow, slice_id)
        assert row is not None and row.status == "failed" and "SLICE_TOO_BROAD" in (row.error or "")


def test_a_slice_whose_finding_vanished_fails(env: tuple[Settings, Engine]) -> None:
    settings, engine = env
    with Session(engine) as s:
        inv = add_upload(s, settings)
        s.add(Job(investigation_id=inv.id, type="slice", params={"slice_id": 12345}))
        for existing in s.scalars(select(Job)):
            if existing.type == "analyze":
                existing.status = "done"
        s.commit()
        job = run_next(s, settings)
        assert job.status == "failed" and "no longer exists" in (job.error or "")
