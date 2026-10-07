"""Worker entrypoint. P0: verify preconditions, then idle. The job loop arrives in P3/P6."""

import logging
import signal
import threading
from types import FrameType

from sqlalchemy.exc import SQLAlchemyError

from app.core.config import get_settings
from app.core.errors import StartupCheckError
from app.core.logging import configure_logging
from app.db.session import check_connection, make_engine
from app.worker.startup import check_attack_mapping, check_data_dirs, check_zeek

logger = logging.getLogger("app.worker")


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
    logger.info("worker ready (idle); zeek %s, ATT&CK %s", version, attack_version)

    stop.wait()
    engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
