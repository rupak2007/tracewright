"""FastAPI application factory. The API never runs Zeek/tcpdump on capture bytes (SEC-02)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import Engine

from app.api.health import router as health_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import make_engine


def create_app(engine: Engine | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings = get_settings()
        configure_logging(settings.log_level)
        app.state.engine = engine if engine is not None else make_engine(settings)
        yield
        app.state.engine.dispose()

    app = FastAPI(title="Tracewright", version="0.1.0", lifespan=lifespan)
    app.include_router(health_router, prefix="/api/v1")
    return app


app = create_app()
