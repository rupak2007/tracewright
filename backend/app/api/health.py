"""GET /api/v1/health: database connectivity and the worker heartbeat (architecture §22)."""

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.schemas import HealthResponse
from app.db import jobs
from app.db.session import check_connection

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse | JSONResponse:
    engine: Engine = request.app.state.engine
    try:
        check_connection(engine)
    except SQLAlchemyError:
        logger.exception("health check: database unreachable")
        return JSONResponse(
            status_code=503,
            content={"error": {"code": "DB_UNAVAILABLE", "message": "Database is unavailable."}},
        )
    try:
        with Session(engine) as session:
            alive = jobs.worker_alive(session)
    except SQLAlchemyError:  # schema not migrated yet: the database is up, the worker unknown
        alive = False
    return HealthResponse(status="ok", db="ok", worker="alive" if alive else "unknown")
