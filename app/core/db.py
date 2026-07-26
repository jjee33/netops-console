"""Async SQLAlchemy engine and session factory.

The pragma listener below is not optional tuning. SQLite disables foreign key
enforcement by default and does so per connection, so without it every
``ON DELETE`` rule in the schema is decorative — including the ones protecting
audit history. WAL and a busy timeout are set in the same place because they
have the same failure mode: fine in development, corrupt or locked under
concurrent writes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all models."""


def _apply_sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    """Set connection-scoped pragmas. Runs for every pooled connection."""
    cursor = dbapi_connection.cursor()
    try:
        # Enforce ON DELETE / ON UPDATE. Off by default, per connection.
        cursor.execute("PRAGMA foreign_keys=ON")
        # Readers do not block the writer. Required for a polling UI over a
        # database that is being written to by background executions.
        cursor.execute("PRAGMA journal_mode=WAL")
        # Absorb brief write contention instead of raising "database is locked".
        cursor.execute("PRAGMA busy_timeout=5000")
        # WAL + NORMAL is durable across application crashes (not power loss),
        # which is the right trade for diagnostic history.
        cursor.execute("PRAGMA synchronous=NORMAL")
    finally:
        cursor.close()


def create_engine(url: str | None = None, **kwargs: Any) -> AsyncEngine:
    settings = get_settings()
    engine = create_async_engine(
        url or settings.database_url,
        # SQLite is single-writer; a large pool buys contention, not throughput.
        pool_pre_ping=True,
        **kwargs,
    )
    event.listen(engine.sync_engine, "connect", _apply_sqlite_pragmas)
    return engine


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _session_factory


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session that commits or rolls back."""
    async with get_session_factory()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
