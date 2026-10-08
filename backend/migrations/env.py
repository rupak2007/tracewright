"""Alembic environment: POSTGRES_* variables give the URL (ALEMBIC_URL overrides it)."""

import os

from alembic import context
from sqlalchemy import create_engine

from app.db.models import Base

target_metadata = Base.metadata


def _url() -> str:
    override = os.environ.get("ALEMBIC_URL")
    if override:
        return override
    from app.core.config import get_settings

    return get_settings().database_url.render_as_string(hide_password=False)


def run_migrations_online() -> None:
    connectable = context.config.attributes.get("connection")
    if connectable is None:
        engine = create_engine(_url())
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()
        engine.dispose()
    else:
        context.configure(connection=connectable, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
