"""Device history, scan report and scan comparison pages.

Everything on these pages came from the network or an operator, so the hostile
cases matter as much as the happy path: a hostname carrying markup must arrive
escaped, and a run recorded before this feature must say so rather than render
as an empty scan.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from tests.conftest import csrf_token

from app.core.db import get_session_factory
from app.models import Device, DiscoveryRun
from app.modules.discovery.parser import ParsedHost, ParsedPort, ParsedScan
from app.modules.discovery.service import reconcile

NETWORK = ipaddress.IPv4Network("10.0.40.0/24")
HOSTILE = "<script>alert(1)</script>"


async def _scan(hosts: list[ParsedHost], *, scanned_ports: bool = True) -> int:
    async with get_session_factory()() as session:
        run = DiscoveryRun(
            subnet=str(NETWORK), status="running", scanned_ports=scanned_ports,
            username_snapshot="admin",
        )  # fmt: skip
        session.add(run)
        await session.commit()
        found, created = await reconcile(
            session, ParsedScan(hosts=hosts), NETWORK, datetime.now(UTC), run=run
        )
        run.status = "success"
        run.devices_found = found
        run.devices_new = created
        await session.commit()
        return run.id


def _host(ip: str, mac: str, *ports: int, hostname: str | None = None) -> ParsedHost:
    return ParsedHost(
        ip_address=ip,
        mac_address=mac,
        hostname=hostname,
        ports=[ParsedPort(port=port, protocol="tcp", state="open") for port in ports],
    )


async def _two_scans() -> tuple[int, int]:
    first = await _scan(
        [
            _host("10.0.40.1", "aa:00:00:00:00:01", 22, 443),
            _host("10.0.40.2", "aa:00:00:00:00:02", 80),
            _host("10.0.40.3", "aa:00:00:00:00:03"),
        ]
    )
    second = await _scan(
        [
            # Same device, new address and a new port: changed, not gone + new.
            _host("10.0.40.11", "aa:00:00:00:00:01", 22, 443, 8443),
            _host("10.0.40.3", "aa:00:00:00:00:03"),
            _host("10.0.40.4", "aa:00:00:00:00:04", hostname=HOSTILE),
        ]
    )
    return first, second


class TestCompare:
    async def test_compare_classifies_hosts(self, auth_client: httpx.AsyncClient) -> None:
        first, second = await _two_scans()
        response = await auth_client.get(f"/discovery/compare?base={first}&target={second}")
        assert response.status_code == 200
        text = response.text

        assert "10.0.40.4" in text  # new
        assert "10.0.40.2" in text  # no longer answering
        assert "IP address: 10.0.40.1 → 10.0.40.11" in text
        assert "Newly open: 8443/tcp" in text
        assert HOSTILE not in text
        assert "&lt;script&gt;" in text

    async def test_defaults_to_the_latest_two_scans_of_a_range(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        first, second = await _two_scans()
        response = await auth_client.get("/discovery/compare")
        assert f"#{first}</a>" in response.text and f"#{second}</a>" in response.text

    async def test_order_is_normalised_to_earlier_then_later(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        first, second = await _two_scans()
        response = await auth_client.get(f"/discovery/compare?base={second}&target={first}")
        assert "Newly open: 8443/tcp" in response.text

    async def test_same_run_twice_is_refused_politely(self, auth_client: httpx.AsyncClient) -> None:
        first, _ = await _two_scans()
        response = await auth_client.get(f"/discovery/compare?base={first}&target={first}")
        assert response.status_code == 200
        assert "two different scans" in response.text

    async def test_unknown_run_is_404(self, auth_client: httpx.AsyncClient) -> None:
        response = await auth_client.get("/discovery/compare?base=998&target=999")
        assert response.status_code == 404

    async def test_ports_are_not_compared_against_a_host_only_scan(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        first = await _scan([_host("10.0.40.1", "aa:00:00:00:00:01", 22)])
        second = await _scan([_host("10.0.40.1", "aa:00:00:00:00:01")], scanned_ports=False)
        response = await auth_client.get(f"/discovery/compare?base={first}&target={second}")
        assert "Ports are not compared" in response.text
        assert "No longer open" not in response.text

    async def test_legacy_run_is_not_presented_as_empty(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        async with get_session_factory()() as session:
            legacy = DiscoveryRun(subnet=str(NETWORK), status="success", devices_found=7)
            session.add(legacy)
            await session.commit()
        current = await _scan([_host("10.0.40.1", "aa:00:00:00:00:01")])

        response = await auth_client.get(f"/discovery/compare?base={legacy.id}&target={current}")
        assert "before per-host scan history existed" in response.text


class TestReport:
    async def test_report_lists_answering_and_silent_hosts(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        _, second = await _two_scans()
        response = await auth_client.get(f"/discovery/runs/{second}/report")
        assert response.status_code == 200
        assert "no answer" in response.text  # 10.0.40.2 did not answer the second scan
        assert "open: 22/tcp, 443/tcp, 8443/tcp" in response.text
        assert HOSTILE not in response.text
        assert f"/discovery/compare?base={second - 1}&amp;target={second}" in response.text

    async def test_report_explains_a_scan_with_no_mac_addresses(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        run_id = await _scan(
            [ParsedHost(ip_address="10.0.40.1"), ParsedHost(ip_address="10.0.40.2")]
        )
        response = await auth_client.get(f"/discovery/runs/{run_id}/report")
        assert "none reported a MAC address" in response.text

    async def test_legacy_run_report(self, auth_client: httpx.AsyncClient) -> None:
        async with get_session_factory()() as session:
            legacy = DiscoveryRun(subnet=str(NETWORK), status="success", devices_found=3)
            session.add(legacy)
            await session.commit()
        response = await auth_client.get(f"/discovery/runs/{legacy.id}/report")
        assert "before per-host scan history existed" in response.text
        assert "not recorded (older scan)" in response.text

    async def test_unknown_report_is_404(self, auth_client: httpx.AsyncClient) -> None:
        assert (await auth_client.get("/discovery/runs/999/report")).status_code == 404


class TestDeviceHistory:
    async def test_history_shows_scan_changes_and_operator_edits(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _two_scans()
        async with get_session_factory()() as session:
            device = await session.scalar(
                select(Device).where(Device.mac_address == "aa:00:00:00:00:01")
            )
            assert device
            device_id = device.id

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}",
            data={"name": HOSTILE, "device_type": "", "notes": "", "csrf_token": token},
        )

        response = await auth_client.get(f"/devices/{device_id}/history")
        assert response.status_code == 200
        text = response.text
        assert "First recorded by scan" in text
        assert "IP address: 10.0.40.1 → 10.0.40.11" in text
        assert "Device details edited" in text
        assert "<strong>2</strong> of them" in text
        assert HOSTILE not in text

        detail = await auth_client.get(f"/devices/{device_id}")
        assert "Recent activity" in detail.text
        assert f"/devices/{device_id}/history" in detail.text

    async def test_device_that_stopped_answering(self, auth_client: httpx.AsyncClient) -> None:
        await _two_scans()
        async with get_session_factory()() as session:
            device_id = await session.scalar(
                select(Device.id).where(Device.mac_address == "aa:00:00:00:00:02")
            )
        response = await auth_client.get(f"/devices/{device_id}/history")
        assert "Did not answer scan" in response.text

    async def test_removed_device_history_is_404(self, auth_client: httpx.AsyncClient) -> None:
        async with get_session_factory()() as session:
            device = Device(ip_address="10.0.40.9", status="online", is_deleted=True)
            session.add(device)
            await session.commit()
        response = await auth_client.get(f"/devices/{device.id}/history")
        assert response.status_code == 404

    async def test_pages_require_login(self, client: httpx.AsyncClient) -> None:
        for path in ("/devices/1/history", "/discovery/runs/1/report", "/discovery/compare"):
            response = await client.get(path)
            assert response.status_code in (302, 303), path


class TestAuditIncludesChanges:
    async def test_change_filter(self, auth_client: httpx.AsyncClient) -> None:
        async with get_session_factory()() as session:
            device = Device(ip_address="10.0.40.9", status="online")
            session.add(device)
            await session.commit()
        token = await csrf_token(auth_client, f"/devices/{device.id}")
        await auth_client.post(
            f"/devices/{device.id}",
            data={"name": "edge-router", "device_type": "", "notes": "", "csrf_token": token},
        )

        response = await auth_client.get("/audit?kind=change")
        assert "Device details edited" in response.text
        assert "edge-router" in response.text

        everything = await auth_client.get("/audit")
        assert "Device details edited" in everything.text


class TestExplanationRendering:
    async def test_stored_result_renders_its_explanation_escaped(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        from app.models import DiagnosticResult

        async with get_session_factory()() as session:
            result = DiagnosticResult(
                type="tcp",
                target="10.0.40.5",
                status="success",
                output=f"PORT   STATE  SERVICE\n22/tcp closed ssh\n{HOSTILE}\n",
                started_at=datetime.now(UTC),
            )
            session.add(result)
            await session.commit()

        response = await auth_client.get(f"/diagnostics/{result.id}")
        assert "nothing is listening on 22/tcp" in response.text
        assert "Likely causes" in response.text
        assert HOSTILE not in response.text
