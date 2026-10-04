"""GET /api/v1/health: database connectivity. Worker heartbeat arrives with the jobs table."""

import logging
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import check_connection

router = APIRouter()
logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    status: Literal["ok"]
    db: Literal["ok"]


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
    return HealthResponse(status="ok", db="ok")
