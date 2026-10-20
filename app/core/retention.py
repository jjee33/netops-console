"""Pruning execution history.

Not optional, and not a tidiness feature. Every diagnostic result and every
action execution carries an output blob. A device page that is used regularly
produces them steadily, nothing ever removes them on its own, and each one is
copied into every backup taken from then on.

Both tables are pruned together and to the same window, because they are the
same kind of record and an operator setting "keep 90 days" means all of it.
Per-host scan observations follow the same window for the same reason: there is
one per device per scan, and they are what device history is built from, so
"keep 90 days" bounds how far back that history reaches.

Discovery runs are deliberately left alone: they are small, there is one per
scan rather than one per click, and they are the cheapest answer to "when did
this device first appear on my network". So is the change log, which grows only
when an operator changes something.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ActionExecution, DiagnosticResult, DiscoveryObservation

logger = logging.getLogger("netops.retention")


@dataclass(frozen=True)
class PruneResult:
    diagnostics: int
    actions: int
    observations: int = 0

    @property
    def total(self) -> int:
        return self.diagnostics + self.actions + self.observations


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
    observations = await session.execute(
        delete(DiscoveryObservation).where(DiscoveryObservation.observed_at < cutoff)
    )
    await session.commit()

    # CursorResult carries rowcount; the base Result type does not, and mypy
    # only sees the latter on an async execute.
    result = PruneResult(
        diagnostics=getattr(diagnostics, "rowcount", 0) or 0,
        actions=getattr(actions, "rowcount", 0) or 0,
        observations=getattr(observations, "rowcount", 0) or 0,
    )

    if result.total:
        logger.info(
            "pruned %d diagnostic result(s), %d action execution(s) and %d scan "
            "observation(s) older than %d days",
            result.diagnostics,
            result.actions,
            result.observations,
            retention_days,
        )
    return result
