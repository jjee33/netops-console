"""Device pages and the discovery request path.

The scan itself is not executed here — that needs a real network and is covered
by the manual checklist. What is tested is everything around it: that an
out-of-scope or oversized range never reaches nmap, and that deleting a device
does not destroy history.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import func, select
from tests.conftest import csrf_token

from app.core.db import get_session_factory
from app.models import Device, DiscoveryRun
from app.modules.discovery.parser import ParsedHost
from app.modules.discovery.service import upsert_device


async def _seed_device(**overrides: object) -> int:
    async with get_session_factory()() as session:
        host = ParsedHost(
            ip_address=str(overrides.get("ip", "192.168.1.10")),
            mac_address=str(overrides.get("mac", "aa:bb:cc:dd:ee:ff")),
            vendor="Ubiquiti Inc",
            hostname="switch.lan",
        )
        device, _ = await upsert_device(session, host)
        await session.commit()
        return device.id


class TestDeviceList:
    async def test_empty_inventory_renders(self, auth_client: httpx.AsyncClient) -> None:
        response = await auth_client.get("/devices")
        assert response.status_code == 200
        assert "No devices" in response.text

    async def test_a_device_appears(self, auth_client: httpx.AsyncClient) -> None:
        await _seed_device()
        response = await auth_client.get("/devices")
        assert "192.168.1.10" in response.text
        assert "Ubiquiti Inc" in response.text

    @pytest.mark.parametrize("sort", ["ip", "name", "hostname", "vendor", "status", "last_seen"])
    async def test_every_sort_column_works(self, auth_client: httpx.AsyncClient, sort: str) -> None:
        await _seed_device()
        assert (await auth_client.get(f"/devices?sort={sort}")).status_code == 200

    async def test_an_unknown_sort_column_falls_back_rather_than_erroring(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """The sort key comes from a query string, so it is user input. It
        selects from a fixed map and is never interpolated into SQL."""
        await _seed_device()
        response = await auth_client.get("/devices?sort=password_hash;DROP TABLE device")
        assert response.status_code == 200

        async with get_session_factory()() as session:
            assert await session.scalar(select(func.count()).select_from(Device)) == 1

    async def test_search_matches_and_filters(self, auth_client: httpx.AsyncClient) -> None:
        await _seed_device()
        assert "192.168.1.10" in (await auth_client.get("/devices?q=ubiquiti")).text
        assert "192.168.1.10" not in (await auth_client.get("/devices?q=nothingmatches")).text

    async def test_search_input_is_not_treated_as_sql(self, auth_client: httpx.AsyncClient) -> None:
        await _seed_device()
        response = await auth_client.get("/devices?q=' OR 1=1 --")
        assert response.status_code == 200
        assert "192.168.1.10" not in response.text

    async def test_htmx_gets_a_fragment_not_a_whole_page(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await auth_client.get("/devices", headers={"HX-Request": "true"})
        assert "<table" in response.text
        assert "<html" not in response.text


class TestDeviceDetail:
    async def test_shows_the_device(self, auth_client: httpx.AsyncClient) -> None:
        device_id = await _seed_device()
        response = await auth_client.get(f"/devices/{device_id}")
        assert response.status_code == 200
        assert "aa:bb:cc:dd:ee:ff" in response.text

    async def test_a_missing_device_is_a_404(self, auth_client: httpx.AsyncClient) -> None:
        assert (await auth_client.get("/devices/99999")).status_code == 404

    async def test_operator_fields_can_be_edited(self, auth_client: httpx.AsyncClient) -> None:
        device_id = await _seed_device()
        token = await csrf_token(auth_client, f"/devices/{device_id}")

        response = await auth_client.post(
            f"/devices/{device_id}",
            data={
                "name": "Core switch",
                "device_type": "switch",
                "notes": "Rack 2",
                "csrf_token": token,
            },
        )
        assert response.status_code == 303

        async with get_session_factory()() as session:
            device = await session.get(Device, device_id)
            assert device and device.name == "Core switch"

    async def test_a_hostile_hostname_is_rendered_escaped(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """Hostnames come from reverse DNS, which an attacker on the network may
        control. This is the stored-XSS path."""
        async with get_session_factory()() as session:
            device, _ = await upsert_device(
                session,
                ParsedHost(
                    ip_address="192.168.1.66",
                    mac_address="11:22:33:44:55:66",
                    hostname="<script>alert('xss')</script>",
                ),
            )
            await session.commit()
            device_id = device.id

        for path in (f"/devices/{device_id}", "/devices"):
            response = await auth_client.get(path)
            assert "<script>alert('xss')</script>" not in response.text
            assert "&lt;script&gt;" in response.text


class TestSoftDelete:
    async def test_delete_hides_the_device_but_keeps_the_row(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _seed_device()
        token = await csrf_token(auth_client, f"/devices/{device_id}")

        response = await auth_client.post(
            f"/devices/{device_id}/delete", data={"csrf_token": token}
        )
        assert response.status_code == 303

        assert "192.168.1.10" not in (await auth_client.get("/devices")).text
        assert (await auth_client.get(f"/devices/{device_id}")).status_code == 404

        async with get_session_factory()() as session:
            device = await session.get(Device, device_id)
            assert device is not None, "the row was hard-deleted; audit history would be lost"
            assert device.is_deleted is True
            assert device.deleted_at is not None

    async def test_deleting_a_device_preserves_discovery_history(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _seed_device()

        async with get_session_factory()() as session:
            session.add(
                DiscoveryRun(
                    subnet="192.168.1.0/24",
                    status="success",
                    devices_found=1,
                    username_snapshot="admin",
                    started_at=datetime.now(UTC),
                )
            )
            await session.commit()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(f"/devices/{device_id}/delete", data={"csrf_token": token})

        async with get_session_factory()() as session:
            runs = await session.scalar(select(func.count()).select_from(DiscoveryRun))
            assert runs == 1


class TestDiscoveryRequests:
    async def _start(self, client: httpx.AsyncClient, subnet: str) -> httpx.Response:
        token = await csrf_token(client, "/discovery")
        return await client.post("/discovery/run", data={"subnet": subnet, "csrf_token": token})

    async def test_a_public_range_is_refused_before_any_scan_runs(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await self._start(auth_client, "8.8.8.0/24")
        assert response.status_code == 400
        assert "outside the configured" in response.text

        async with get_session_factory()() as session:
            # Nothing was recorded, because nothing was attempted.
            assert await session.scalar(select(func.count()).select_from(DiscoveryRun)) == 0

    @pytest.mark.parametrize("subnet", ["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"])
    async def test_reserved_ranges_are_refused(
        self, auth_client: httpx.AsyncClient, subnet: str
    ) -> None:
        assert (await self._start(auth_client, subnet)).status_code == 400

    async def test_an_oversized_range_is_refused(self, auth_client: httpx.AsyncClient) -> None:
        """A mistyped prefix must not become a scan of sixteen million hosts."""
        response = await self._start(auth_client, "10.0.0.0/8")
        assert response.status_code == 400
        assert "above the limit" in response.text

    @pytest.mark.parametrize("subnet", ["not-a-subnet", "10.0.0.1", "10.0.0.0/33", ""])
    async def test_malformed_input_is_refused(
        self, auth_client: httpx.AsyncClient, subnet: str
    ) -> None:
        response = await self._start(auth_client, subnet)
        assert response.status_code in (400, 422)

    async def test_the_history_page_renders(self, auth_client: httpx.AsyncClient) -> None:
        assert (await auth_client.get("/discovery")).status_code == 200

    async def test_run_status_for_a_missing_run_is_a_404(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        assert (await auth_client.get("/discovery/runs/9999")).status_code == 404


class TestAccessControl:
    @pytest.mark.parametrize("path", ["/devices", "/devices/1", "/discovery", "/discovery/runs/1"])
    async def test_pages_require_authentication(self, client: httpx.AsyncClient, path: str) -> None:
        response = await client.get(path)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")

    async def test_starting_a_scan_requires_authentication(self, client: httpx.AsyncClient) -> None:
        response = await client.post("/discovery/run", data={"subnet": "10.0.0.0/24"})
        # CSRF is checked first, so this is a 403 rather than a redirect —
        # either way the scan does not run.
        assert response.status_code in (303, 403)
