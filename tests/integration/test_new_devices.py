"""New-device awareness.

An unfamiliar MAC appearing on the LAN is the most actionable signal a tool like
this can give. A list of forty devices is not — the point of this feature is to
turn the inventory into something worth glancing at.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from app.core.db import get_session_factory
from app.models import Device


async def _device(ip: str, first_seen: datetime, mac: str | None = None) -> int:
    async with get_session_factory()() as session:
        device = Device(
            ip_address=ip,
            mac_address=mac,
            first_seen=first_seen,
            last_seen=datetime.now(UTC),
            status="online",
        )
        session.add(device)
        await session.commit()
        return device.id


class TestDashboardTile:
    async def test_counts_only_recent_arrivals(self, auth_client: httpx.AsyncClient) -> None:
        now = datetime.now(UTC)
        await _device("10.0.30.10", now - timedelta(days=1), "aa:aa:aa:aa:aa:aa")
        await _device("10.0.30.11", now - timedelta(days=3), "bb:bb:bb:bb:bb:bb")
        await _device("10.0.30.12", now - timedelta(days=90), "cc:cc:cc:cc:cc:cc")

        response = await auth_client.get("/")
        assert response.status_code == 200
        assert "New (7d)" in response.text
        assert "Appeared in the last 7 days" in response.text

    async def test_new_devices_are_named_not_just_counted(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """'Three devices appeared' is a prompt; naming them is what makes it
        possible to act."""
        await _device("10.0.30.77", datetime.now(UTC) - timedelta(hours=2), "de:ad:be:ef:00:01")

        response = await auth_client.get("/")
        assert "10.0.30.77" in response.text
        assert "de:ad:be:ef:00:01" in response.text

    async def test_the_section_is_absent_when_nothing_is_new(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _device("10.0.30.12", datetime.now(UTC) - timedelta(days=90))
        response = await auth_client.get("/")
        assert "Appeared in the last" not in response.text

    async def test_a_deleted_device_does_not_count_as_new(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device("10.0.30.13", datetime.now(UTC) - timedelta(hours=1))
        async with get_session_factory()() as session:
            device = await session.get(Device, device_id)
            assert device
            device.is_deleted = True
            await session.commit()

        response = await auth_client.get("/")
        assert "10.0.30.13" not in response.text


class TestDeviceListFilter:
    async def test_the_filter_shows_only_recent_arrivals(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        now = datetime.now(UTC)
        await _device("10.0.30.20", now - timedelta(days=2))
        await _device("10.0.30.21", now - timedelta(days=200))

        filtered = await auth_client.get("/devices?new=1")
        assert "10.0.30.20" in filtered.text
        assert "10.0.30.21" not in filtered.text

    async def test_the_unfiltered_list_shows_everything(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        now = datetime.now(UTC)
        await _device("10.0.30.20", now - timedelta(days=2))
        await _device("10.0.30.21", now - timedelta(days=200))

        everything = await auth_client.get("/devices")
        assert "10.0.30.20" in everything.text
        assert "10.0.30.21" in everything.text

    async def test_the_filter_survives_a_search(self, auth_client: httpx.AsyncClient) -> None:
        now = datetime.now(UTC)
        await _device("10.0.30.30", now - timedelta(days=1))
        await _device("10.0.40.30", now - timedelta(days=1))
        await _device("10.0.30.31", now - timedelta(days=300))

        response = await auth_client.get("/devices?new=1&q=10.0.30.")
        assert "10.0.30.30" in response.text
        assert "10.0.40.30" not in response.text
        assert "10.0.30.31" not in response.text

    async def test_the_filter_works_with_htmx(self, auth_client: httpx.AsyncClient) -> None:
        await _device("10.0.30.40", datetime.now(UTC) - timedelta(days=1))
        response = await auth_client.get("/devices?new=1", headers={"HX-Request": "true"})
        assert "<table" in response.text
        assert "<html" not in response.text

    async def test_a_junk_filter_value_shows_everything_rather_than_erroring(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _device("10.0.30.50", datetime.now(UTC) - timedelta(days=300))
        response = await auth_client.get("/devices?new=maybe")
        assert response.status_code == 200
        assert "10.0.30.50" in response.text
