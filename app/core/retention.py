"""Pruning execution history.

Not optional, and not a tidiness feature. Every diagnostic result and every
action execution carries an output blob. A device page that is used regularly
produces them steadily, nothing ever removes them on its own, and each one is
copied into every backup taken from then on.

Both tables are pruned together and to the same window, because they are the
same kind of record and an operator setting "keep 90 days" means all of it.
Discovery runs are deliberately left alone: they are small, there is one per
scan rather than one per click, and they are the cheapest answer to "when did
this device first appear on my network".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ActionExecution, DiagnosticResult

logger = logging.getLogger("netops.retention")


@dataclass(frozen=True)
class PruneResult:
    diagnostics: int
    actions: int

    @property
    def total(self) -> int:
        return self.diagnostics + self.actions


async def prune(session: AsyncSession, retention_days: int) -> PruneResult:
    """Delete execution history older than the window.

    A zero or negative window deletes nothing. It is far more likely to be a
    misconfiguration than an instruction to discard the entire audit trail, and
    the destructive reading of an ambiguous value is the wrong one to take.
    """
    if retention_days < 1:
        return PruneResult(0, 0)

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)

    diagnostics = await session.execute(
        delete(DiagnosticResult).where(DiagnosticResult.started_at < cutoff)
    )
    actions = await session.execute(
        delete(ActionExecution).where(ActionExecution.started_at < cutoff)
    )
    await session.commit()

    # CursorResult carries rowcount; the base Result type does not, and mypy
    # only sees the latter on an async execute.
    result = PruneResult(
        diagnostics=getattr(diagnostics, "rowcount", 0) or 0,
        actions=getattr(actions, "rowcount", 0) or 0,
    )

    if result.total:
        logger.info(
            "pruned %d diagnostic result(s) and %d action execution(s) older than %d days",
            result.diagnostics,
            result.actions,
            retention_days,
        )
    return result
