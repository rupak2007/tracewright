"""Worker entrypoint: verify preconditions, then lease and run jobs until told to stop."""

import logging
import signal
import socket
import threading
from types import FrameType

from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.errors import StartupCheckError
from app.core.logging import configure_logging
from app.db import jobs
from app.db.session import check_connection, make_engine
from app.worker.analysis_config import load_analysis_config
from app.worker.jobs_runner import process
from app.worker.startup import check_attack_mapping, check_data_dirs, check_zeek

logger = logging.getLogger("app.worker")
POLL_S = 2.0


def _heartbeat(engine: Engine, worker_id: str, stop: threading.Event) -> None:
    """Every HEARTBEAT_S: record liveness and extend the lease of every job this worker runs."""
    while not stop.wait(jobs.HEARTBEAT_S):
        try:
            with Session(engine) as session:
                jobs.beat(session, worker_id)
                for job in jobs.running_for(session, worker_id):
                    jobs.extend_lease(session, job)
                session.commit()
        except SQLAlchemyError:
            logger.warning("heartbeat failed", exc_info=True)


def run_loop(engine: Engine, settings: Settings, stop: threading.Event) -> None:
    worker_id = f"{socket.gethostname()}-{threading.get_ident()}"
    severity = load_analysis_config(settings).correlation.severity
    beat = threading.Thread(target=_heartbeat, args=(engine, worker_id, stop), daemon=True)
    with Session(engine) as session:
        jobs.beat(session, worker_id)
        session.commit()
    beat.start()
    while not stop.is_set():
        try:
            with Session(engine) as session:
                job = jobs.claim(session, worker_id=worker_id)
                session.commit()
                if job is not None:
                    logger.info("running job %s (%s)", job.id, job.type)
                    process(session, settings, job, severity)
                    continue
        except SQLAlchemyError:  # database restarting or not migrated yet: wait and retry
            logger.warning("job loop: database error, retrying", exc_info=True)
        stop.wait(POLL_S)


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)

    stop = threading.Event()

    def _request_stop(signum: int, _frame: FrameType | None) -> None:
        logger.info("received signal %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    engine = make_engine(settings)
    try:
        version = check_zeek(settings)
        attack_version = check_attack_mapping(settings)
        check_data_dirs(settings)
        check_connection(engine)
    except StartupCheckError as exc:
        logger.error("startup check failed: %s", exc.message)
        return 1
    except SQLAlchemyError as exc:
        logger.error("startup check failed: database unreachable (%s)", type(exc).__name__)
        return 1
    logger.info("worker ready; zeek %s, ATT&CK %s", version, attack_version)

    run_loop(engine, settings, stop)
    engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
