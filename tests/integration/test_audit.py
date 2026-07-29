"""The audit log.

One timeline over everything, because the question an operator asks is "what
happened to my network", not "what did the diagnostics subsystem do". Refusals
appear alongside successes for the same reason they are recorded at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.db import get_session_factory
from app.models import DiagnosticResult, DiscoveryRun


async def _seed(diagnostics: int = 3, runs: int = 2) -> None:
    base = datetime.now(UTC)
    async with get_session_factory()() as session:
        for index in range(diagnostics):
            session.add(
                DiagnosticResult(
                    type="ping",
                    target=f"10.0.30.{index + 1}",
                    status="success" if index % 2 == 0 else "rejected",
                    output="pong",
                    username_snapshot="admin",
                    client_ip="10.0.30.99",
                    started_at=base - timedelta(minutes=index),
                    duration_ms=12,
                )
            )
        for index in range(runs):
            session.add(
                DiscoveryRun(
                    subnet=f"10.0.{index}.0/24",
                    status="success",
                    devices_found=index,
                    username_snapshot="admin",
                    client_ip="10.0.30.99",
                    started_at=base - timedelta(hours=index + 1),
                )
            )
        await session.commit()


class TestAuditView:
    async def test_empty_state(self, auth_client: httpx.AsyncClient) -> None:
        response = await auth_client.get("/audit")
        assert response.status_code == 200
        assert "Nothing recorded yet" in response.text

    async def test_shows_both_sources_in_one_timeline(self, auth_client: httpx.AsyncClient) -> None:
        await _seed()
        response = await auth_client.get("/audit")

        assert response.status_code == 200
        assert "Ping" in response.text
        assert "Discovery scan" in response.text

    async def test_refusals_appear_alongside_successes(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """A log that only shows what worked hides exactly the entries an
        operator is looking for."""
        await _seed()
        response = await auth_client.get("/audit")
        assert "rejected" in response.text
        assert "success" in response.text

    async def test_newest_first(self, auth_client: httpx.AsyncClient) -> None:
        await _seed()
        text = (await auth_client.get("/audit")).text
        # The most recent diagnostic targets .1 and the oldest run is an hour
        # back, so the diagnostic must appear before the scan.
        assert text.index("10.0.30.1") < text.index("10.0.0.0/24")

    async def test_attribution_is_shown(self, auth_client: httpx.AsyncClient) -> None:
        await _seed()
        response = await auth_client.get("/audit")
        assert "admin" in response.text
        assert "10.0.30.99" in response.text

    @pytest.mark.parametrize(
        ("kind", "present", "absent"),
        [("diagnostic", "Ping", "Discovery scan"), ("discovery", "Discovery scan", "Ping")],
    )
    async def test_filtering(
        self, auth_client: httpx.AsyncClient, kind: str, present: str, absent: str
    ) -> None:
        await _seed()
        response = await auth_client.get(f"/audit?kind={kind}")
        assert present in response.text
        assert absent not in response.text

    async def test_an_unknown_filter_shows_nothing_rather_than_everything(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """Fails closed: an unrecognised filter must not silently widen the view."""
        await _seed()
        response = await auth_client.get("/audit?kind=not-a-real-kind")
        assert response.status_code == 200
        assert "Ping" not in response.text
        assert "Discovery scan" not in response.text


class TestPagination:
    async def test_a_full_page_offers_older_entries(self, auth_client: httpx.AsyncClient) -> None:
        await _seed(diagnostics=60, runs=0)
        response = await auth_client.get("/audit")
        assert "Older entries" in response.text

    async def test_a_short_page_does_not(self, auth_client: httpx.AsyncClient) -> None:
        await _seed(diagnostics=3, runs=1)
        assert "Older entries" not in (await auth_client.get("/audit")).text

    async def test_the_cursor_advances_through_the_list(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _seed(diagnostics=60, runs=0)
        first = await auth_client.get("/audit")

        import re

        match = re.search(r'/audit\?before=([^"&]+)', first.text)
        assert match, "no pagination cursor rendered"

        second = await auth_client.get(f"/audit?before={match.group(1)}")
        assert second.status_code == 200
        # The newest entry must not reappear on the following page.
        assert "10.0.30.1<" not in second.text

    @pytest.mark.parametrize("cursor", ["garbage", "", "'; DROP TABLE device; --", "9999"])
    async def test_a_malformed_cursor_shows_the_first_page(
        self, auth_client: httpx.AsyncClient, cursor: str
    ) -> None:
        """A cursor is a position in a list, not a security boundary — but it is
        still user input reaching a query."""
        await _seed()
        response = await auth_client.get(f"/audit?before={cursor}")
        assert response.status_code == 200
        assert "Ping" in response.text


class TestAccessControl:
    async def test_the_audit_log_requires_authentication(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/audit")
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")


class TestEscaping:
    async def test_hostile_detail_text_is_escaped(self, auth_client: httpx.AsyncClient) -> None:
        """Detail can quote operator input or device-supplied text."""
        async with get_session_factory()() as session:
            session.add(
                DiscoveryRun(
                    subnet="10.0.30.0/24",
                    status="failed",
                    output_summary="<script>alert('xss')</script>",
                    started_at=datetime.now(UTC),
                )
            )
            await session.commit()

        response = await auth_client.get("/audit")
        assert "<script>alert('xss')</script>" not in response.text
        assert "&lt;script&gt;" in response.text


class TestActionsInTheTimeline:
    """Actions were missing from the audit log entirely.

    The page says "everything this instance has done". A log that silently omits
    a whole category of execution is worse than one that admits its scope.
    """

    async def _seed_action(self, status: str = "success") -> None:
        from app.models import ActionExecution

        async with get_session_factory()() as session:
            session.add(
                ActionExecution(
                    action_name_snapshot="Restart nginx",
                    device_label_snapshot="10.0.30.5",
                    username_snapshot="admin",
                    client_ip="10.0.30.99",
                    command_preview="systemctl restart nginx",
                    status=status,
                    started_at=datetime.now(UTC),
                    duration_ms=340,
                )
            )
            await session.commit()

    async def test_actions_appear_in_the_combined_view(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await self._seed_action()
        response = await auth_client.get("/audit")
        assert "Restart nginx" in response.text

    async def test_the_command_that_ran_is_shown(self, auth_client: httpx.AsyncClient) -> None:
        """The single most useful field for working out what an action did."""
        await self._seed_action()
        response = await auth_client.get("/audit")
        assert "systemctl restart nginx" in response.text

    async def test_actions_can_be_filtered(self, auth_client: httpx.AsyncClient) -> None:
        await self._seed_action()
        await _seed(diagnostics=2, runs=1)

        response = await auth_client.get("/audit?kind=action")
        assert "Restart nginx" in response.text
        assert "Discovery scan" not in response.text
        assert "Ping" not in response.text

    async def test_refused_actions_are_shown_too(self, auth_client: httpx.AsyncClient) -> None:
        await self._seed_action(status="rejected")
        response = await auth_client.get("/audit")
        assert "rejected" in response.text

    async def test_all_three_sources_interleave_by_time(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _seed(diagnostics=2, runs=1)
        await self._seed_action()

        response = await auth_client.get("/audit")
        assert "Restart nginx" in response.text
        assert "Ping" in response.text
        assert "Discovery scan" in response.text
