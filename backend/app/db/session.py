"""Database engine construction and connectivity check. Schema changes go through Alembic only."""

from sqlalchemy import Engine, create_engine, text

from app.core.config import Settings


def make_engine(settings: Settings) -> Engine:
    return create_engine(settings.database_url, pool_pre_ping=True)


def check_connection(engine: Engine) -> None:
    """Raise sqlalchemy.exc.SQLAlchemyError if the database is unreachable."""
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
