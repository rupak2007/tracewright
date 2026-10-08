"""PostgreSQL-only behaviour: the Alembic migration matches the models, and `SKIP LOCKED` hands
every job to exactly one of several concurrent workers.

Runs only when TEST_DATABASE_URL points at an EMPTY PostgreSQL database (the test drops and
recreates the public schema), for example:

    docker run -d --rm --name tw-pg -p 55432:5432 -e POSTGRES_PASSWORD=pw postgres:16
    export TEST_DATABASE_URL=postgresql+psycopg://postgres:pw@127.0.0.1:55432/postgres
    pytest tests/integration/test_postgres.py
"""

import os
import threading
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from app.db import jobs
from app.db.models import Base, Investigation

URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(URL is None, reason="TEST_DATABASE_URL not set")
BACKEND = Path(__file__).resolve().parents[2]


@pytest.fixture
def migrated(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    assert URL is not None
    engine = create_engine(URL)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    monkeypatch.setenv("ALEMBIC_URL", URL)
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    command.upgrade(cfg, "head")
    yield engine, cfg
    engine.dispose()


def test_the_migration_creates_every_model_table_and_matches_the_models(migrated) -> None:  # type: ignore[no-untyped-def]
    engine, cfg = migrated
    assert set(Base.metadata.tables) <= set(inspect(engine).get_table_names())
    command.check(cfg)  # raises if the models and the migration have drifted apart
    with engine.connect() as conn:
        kind = conn.execute(
            text(
                "select data_type from information_schema.columns "
                "where table_name='findings' and column_name='metrics'"
            )
        ).scalar_one()
    assert kind == "jsonb"


def test_downgrade_removes_the_schema(migrated) -> None:  # type: ignore[no-untyped-def]
    engine, cfg = migrated
    command.downgrade(cfg, "base")
    assert "investigations" not in inspect(engine).get_table_names()


def test_concurrent_workers_never_claim_the_same_job(migrated) -> None:  # type: ignore[no-untyped-def]
    engine, _ = migrated
    with Session(engine) as s:
        s.add(Investigation(id="i", upload_name="i.pcap", sha256="a" * 64, size_bytes=1))
        s.flush()
        for _ in range(30):
            jobs.enqueue(s, "i", "analyze")
        s.commit()
    claimed: list[list[int]] = [[] for _ in range(4)]

    def work(slot: int) -> None:
        while True:
            with Session(engine) as session:
                job = jobs.claim(session, worker_id=f"w{slot}")
                session.commit()
                if job is None:
                    return
                claimed[slot].append(job.id)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    every = [j for slot in claimed for j in slot]
    assert len(every) == 30 and len(set(every)) == 30  # each job exactly once
    assert sum(1 for slot in claimed if slot) >= 2  # and the work really was shared
