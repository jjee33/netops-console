"""Alembic environment.

Two settings here are load-bearing on SQLite and are easy to add too late:

``render_as_batch=True``
    SQLite cannot ALTER or DROP a column conventionally. Batch mode makes
    Alembic emit the copy-and-rename dance instead. Without it from the very
    first revision, the first column change becomes a hand-written table
    rebuild.

``PRAGMA foreign_keys``
    Left OFF during migrations on purpose. Batch mode recreates tables, and
    with enforcement on, SQLite would rewrite dependent foreign keys to point
    at the temporary table. The application connection turns it ON — see
    app/core/db.py.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection

from app.core.config import get_settings
from app.core.db import Base

# Importing the package registers every model on Base.metadata. Without this,
# autogenerate produces an empty migration and the schema drifts silently.
import app.models  # noqa: F401  # isort: skip

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    # Deliberately NOT app.core.db.create_engine: that one attaches a listener
    # setting PRAGMA foreign_keys=ON, which is correct for the application and
    # wrong here. See the module docstring.
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_database_url(), poolclass=None)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_do_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
