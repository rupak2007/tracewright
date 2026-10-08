"""FastAPI application factory. The API never runs Zeek/tcpdump on capture bytes (SEC-02)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Engine

from app.api.errors import install_error_handlers
from app.api.health import router as health_router
from app.api.incidents import router as incidents_router
from app.api.investigations import router as investigations_router
from app.core.config import get_api_settings, get_settings
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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_api_settings().cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    install_error_handlers(app)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(investigations_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    return app


app = create_app()
