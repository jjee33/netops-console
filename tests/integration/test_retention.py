"""Retention pruning across both execution tables.

Diagnostic results were pruned from the start; action executions were not, and
accumulated the same output blobs with nothing ever removing them. Both are now
covered by one policy, because they are the same kind of record and an operator
setting "keep 90 days" means all of it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.core.db import get_session_factory
from app.core.retention import prune
from app.models import ActionExecution, DiagnosticResult, DiscoveryRun


async def _seed(ages_in_days: list[int]) -> None:
    now = datetime.now(UTC)
    async with get_session_factory()() as session:
        for age in ages_in_days:
            when = now - timedelta(days=age)
            session.add(
                DiagnosticResult(
                    type="ping",
                    target="10.0.30.5",
                    status="success",
                    output="x" * 500,
                    started_at=when,
                )
            )
            session.add(
                ActionExecution(
                    action_name_snapshot="Show routes",
                    device_label_snapshot="10.0.30.5",
                    status="success",
                    stdout="y" * 500,
                    started_at=when,
                )
            )
            session.add(DiscoveryRun(subnet="10.0.30.0/24", status="success", started_at=when))
        await session.commit()


async def _counts() -> tuple[int, int, int]:
    async with get_session_factory()() as session:
        return (
            await session.scalar(select(func.count()).select_from(DiagnosticResult)) or 0,
            await session.scalar(select(func.count()).select_from(ActionExecution)) or 0,
            await session.scalar(select(func.count()).select_from(DiscoveryRun)) or 0,
        )


class TestPruning:
    async def test_both_execution_tables_are_pruned(self, migrated) -> None:
        """The gap this closes: action executions were never pruned at all."""
        await _seed([1, 30, 100, 400])

        async with get_session_factory()() as session:
            result = await prune(session, retention_days=90)

        assert result.diagnostics == 2
        assert result.actions == 2
        assert result.total == 4

        diagnostics, actions, _ = await _counts()
        assert diagnostics == 2
        assert actions == 2

    async def test_discovery_runs_are_deliberately_kept(self, migrated) -> None:
        """Small, one per scan rather than one per click, and the cheapest answer
        to 'when did this device first appear on my network'."""
        await _seed([1, 400])

        async with get_session_factory()() as session:
            await prune(session, retention_days=90)

        _, _, runs = await _counts()
        assert runs == 2

    async def test_nothing_old_enough_means_nothing_removed(self, migrated) -> None:
        await _seed([1, 10])

        async with get_session_factory()() as session:
            assert (await prune(session, retention_days=90)).total == 0

    @pytest.mark.parametrize("window", [0, -1, -365])
    async def test_a_nonsensical_window_deletes_nothing(
        self,
        migrated,
        window: int,
    ) -> None:
        """Far likelier to be a misconfiguration than an instruction to discard
        the audit trail. The destructive reading of an ambiguous value is the
        wrong one to take."""
        await _seed([1, 400])

        async with get_session_factory()() as session:
            assert (await prune(session, retention_days=window)).total == 0

        diagnostics, actions, _ = await _counts()
        assert (diagnostics, actions) == (2, 2)

    async def test_pruning_is_idempotent(self, migrated) -> None:
        await _seed([400])

        async with get_session_factory()() as session:
            assert (await prune(session, retention_days=90)).total == 2
            assert (await prune(session, retention_days=90)).total == 0

    async def test_an_empty_database_is_fine(self, migrated) -> None:
        async with get_session_factory()() as session:
            assert (await prune(session, retention_days=90)).total == 0
