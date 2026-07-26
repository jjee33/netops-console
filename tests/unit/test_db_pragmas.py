"""SQLite does not enforce foreign keys unless told to, per connection.

These assertions exist because the failure mode is silent: every ON DELETE rule
in the schema, including the ones protecting audit history from device deletion,
becomes decorative if the pragma is not applied to the connection actually in
use. Configuring it is not the same as verifying it.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import text

from app.core.db import dispose_engine, get_session_factory


async def test_foreign_keys_enforced_on_session_connection(migrated: Path) -> None:
    async with get_session_factory()() as session:
        result = await session.execute(text("PRAGMA foreign_keys"))
        assert result.scalar() == 1, "foreign key enforcement is OFF"


async def test_wal_journal_mode(migrated: Path) -> None:
    async with get_session_factory()() as session:
        result = await session.execute(text("PRAGMA journal_mode"))
        assert result.scalar() == "wal"


async def test_busy_timeout_is_set(migrated: Path) -> None:
    async with get_session_factory()() as session:
        result = await session.execute(text("PRAGMA busy_timeout"))
        assert result.scalar() == 5000


async def test_pragmas_apply_to_every_pooled_connection(migrated: Path) -> None:
    """A listener on the wrong event applies the pragma to the first connection only."""
    factory = get_session_factory()
    for _ in range(3):
        async with factory() as session:
            assert (await session.execute(text("PRAGMA foreign_keys"))).scalar() == 1
    await dispose_engine()
