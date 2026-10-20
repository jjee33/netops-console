"""What gets written for device history and the change log.

Two properties matter. Scan observations must record what a scan actually
returned and nothing more, so that two scans can be compared honestly. And
every operator change that previously went only to the process log — above all
forgetting a host key, which deletes the record of who trusted it — must leave
a row behind.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy import select
from tests.conftest import csrf_token

from app.core.db import get_session_factory
from app.models import ChangeEvent, Device, DiscoveryObservation, DiscoveryRun, SshHostKey
from app.modules.discovery.parser import ParsedHost, ParsedPort, ParsedScan, parse_scan
from app.modules.discovery.service import reconcile

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NETWORK = ipaddress.IPv4Network("192.168.1.0/24")


async def _run(scanned_ports: bool = True) -> DiscoveryRun:
    async with get_session_factory()() as session:
        run = DiscoveryRun(subnet=str(NETWORK), status="running", scanned_ports=scanned_ports)
        session.add(run)
        await session.commit()
        return run


async def _observations(run_id: int) -> list[DiscoveryObservation]:
    async with get_session_factory()() as session:
        return list(
            await session.scalars(
                select(DiscoveryObservation)
                .where(DiscoveryObservation.run_id == run_id)
                .order_by(DiscoveryObservation.ip_address)
            )
        )


async def _changes() -> list[ChangeEvent]:
    async with get_session_factory()() as session:
        return list(await session.scalars(select(ChangeEvent).order_by(ChangeEvent.id)))


class TestObservations:
    async def test_each_responding_host_is_recorded_with_its_ports(self, migrated: Path) -> None:
        run = await _run()
        scan = parse_scan((FIXTURES / "nmap_typical.xml").read_text())

        async with get_session_factory()() as session:
            await reconcile(session, scan, NETWORK, datetime.now(UTC), run=run)

        rows = await _observations(run.id)
        assert len(rows) == 3
        assert all(row.present and row.device_id for row in rows)
        gateway = next(row for row in rows if row.ip_address == "192.168.1.1")
        assert gateway.hostname == "gateway.lan"
        # 8080 is "filtered" in the fixture: no answer is not an open port.
        assert [entry["port"] for entry in gateway.ports or []] == [22, 443]

    async def test_a_known_device_that_did_not_answer_is_recorded_absent(
        self, migrated: Path
    ) -> None:
        async with get_session_factory()() as session:
            session.add(
                Device(
                    ip_address="192.168.1.77",
                    status="offline",  # already offline: still a fact about this scan
                    last_seen=datetime.now(UTC) - timedelta(days=1),
                )
            )
            # Outside the scanned range, so this scan says nothing about it.
            session.add(
                Device(
                    ip_address="10.9.9.9",
                    status="online",
                    last_seen=datetime.now(UTC) - timedelta(days=1),
                )
            )
            await session.commit()

        run = await _run()
        async with get_session_factory()() as session:
            await reconcile(session, ParsedScan(hosts=[]), NETWORK, datetime.now(UTC), run=run)

        rows = await _observations(run.id)
        assert [(row.ip_address, row.present) for row in rows] == [("192.168.1.77", False)]
        assert rows[0].ports is None

    async def test_ports_are_null_when_the_run_did_not_check_them(self, migrated: Path) -> None:
        """ "Not looked at" must never read as "all closed"."""
        run = await _run(scanned_ports=False)
        scan = ParsedScan(hosts=[ParsedHost(ip_address="192.168.1.5")])
        async with get_session_factory()() as session:
            await reconcile(session, scan, NETWORK, datetime.now(UTC), run=run)

        (row,) = await _observations(run.id)
        assert row.ports is None

    async def test_the_scan_value_is_recorded_not_the_accumulated_one(self, migrated: Path) -> None:
        """The device keeps a hostname it saw once. The observation must not, or
        a hostname that stopped resolving would never show up as a change."""
        first = await _run()
        named = ParsedHost(ip_address="192.168.1.5", mac_address="aa:00:00:00:00:05")
        named.hostname = "nas.lan"
        async with get_session_factory()() as session:
            await reconcile(
                session, ParsedScan(hosts=[named]), NETWORK, datetime.now(UTC), run=first
            )

        second = await _run()
        unnamed = ParsedHost(
            ip_address="192.168.1.5",
            mac_address="aa:00:00:00:00:05",
            ports=[ParsedPort(port=22, protocol="tcp", state="open")],
        )
        async with get_session_factory()() as session:
            await reconcile(
                session, ParsedScan(hosts=[unnamed]), NETWORK, datetime.now(UTC), run=second
            )
            device = await session.scalar(select(Device))
            assert device and device.hostname == "nas.lan"

        (row,) = await _observations(second.id)
        assert row.hostname is None


async def _device(ip: str = "10.0.30.5") -> int:
    async with get_session_factory()() as session:
        device = Device(ip_address=ip, status="online")
        session.add(device)
        await session.commit()
        return device.id


class TestChangeLog:
    async def test_editing_a_device_records_what_changed(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device()
        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}",
            data={"name": "core-sw", "device_type": "", "notes": "x" * 500, "csrf_token": token},
        )

        (event,) = await _changes()
        assert event.kind == "device_edited"
        assert event.device_id == device_id
        assert event.username_snapshot == "admin"
        assert "name: (empty) → “core-sw”" in (event.detail or "")
        # Long notes are reported as changed, not copied.
        assert "notes changed" in (event.detail or "")
        assert "xxxx" not in (event.detail or "")

    async def test_saving_an_unchanged_device_records_nothing(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device()
        token = await csrf_token(auth_client, f"/devices/{device_id}")
        data = {"name": "", "device_type": "", "notes": "", "csrf_token": token}
        await auth_client.post(f"/devices/{device_id}", data=data)
        assert await _changes() == []

    async def test_removing_a_device_is_recorded(self, auth_client: httpx.AsyncClient) -> None:
        device_id = await _device()
        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(f"/devices/{device_id}/delete", data={"csrf_token": token})

        (event,) = await _changes()
        assert (event.kind, event.device_id) == ("device_removed", device_id)

    async def test_forgetting_a_host_key_keeps_who_had_trusted_it(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device()
        async with get_session_factory()() as session:
            session.add(
                SshHostKey(
                    device_id=device_id,
                    key_type="ssh-ed25519",
                    key_base64="AAAA",
                    fingerprint="SHA256:synthetic-fixture",
                    trusted_by_snapshot="alice",
                )
            )
            await session.commit()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(f"/devices/{device_id}/hostkey/revoke", data={"csrf_token": token})

        (event,) = await _changes()
        assert event.kind == "host_key_revoked"
        assert event.subject == "SHA256:synthetic-fixture"
        assert "trusted by alice" in (event.detail or "")

    async def test_forgetting_when_nothing_is_trusted_records_nothing(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device()
        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(f"/devices/{device_id}/hostkey/revoke", data={"csrf_token": token})
        assert await _changes() == []

    async def test_credential_events_never_contain_the_secret(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        secret = "synthetic-password-do-not-log-9f2c"
        token = await csrf_token(auth_client, "/credentials")
        response = await auth_client.post(
            "/credentials",
            data={
                "name": "Switch login",
                "username": "netops",
                "auth_type": "password",
                "secret": secret,
                "csrf_token": token,
            },
        )
        assert response.status_code == 303

        device_id = await _device()
        async with get_session_factory()() as session:
            from app.models import Credential

            credential_id = await session.scalar(select(Credential.id))

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        for _ in range(2):  # the second assignment is a no-op and must not be logged
            await auth_client.post(
                f"/devices/{device_id}/credentials",
                data={"credential_id": str(credential_id), "csrf_token": token},
            )

        events = await _changes()
        assert [event.kind for event in events] == ["credential_created", "credential_assigned"]
        for event in events:
            assert secret not in f"{event.subject} {event.detail}"

        audit = await auth_client.get("/audit")
        assert secret not in audit.text

    async def test_action_lifecycle_is_recorded(self, auth_client: httpx.AsyncClient) -> None:
        token = await csrf_token(auth_client, "/actions")
        await auth_client.post(
            "/actions",
            data={
                "name": "Show routes",
                "execution_type": "local",
                "argv_template": json.dumps(["ip", "route", "show"]),
                "timeout_seconds": "10",
                "csrf_token": token,
            },
        )
        async with get_session_factory()() as session:
            from app.models import ActionDefinition

            action_id = await session.scalar(select(ActionDefinition.id))

        await auth_client.post(f"/actions/{action_id}/toggle", data={"csrf_token": token})
        await auth_client.post(f"/actions/{action_id}/delete", data={"csrf_token": token})

        events = await _changes()
        assert [event.kind for event in events] == [
            "action_created",
            "action_disabled",
            "action_deleted",
        ]
        assert events[0].detail == "local: ip route show"

    async def test_settings_changes_name_the_fields(self, auth_client: httpx.AsyncClient) -> None:
        token = await csrf_token(auth_client, "/settings")
        await auth_client.post(
            "/settings",
            data={
                "allowed_cidrs": "10.20.0.0/16",
                "max_scan_hosts": "512",
                "max_concurrent_scans": "1",
                "max_concurrent_executions": "4",
                "retention_days": "90",
                "csrf_token": token,
            },
        )

        (event,) = await _changes()
        assert event.kind == "settings_changed"
        assert "allowed ranges" in (event.detail or "")
        assert "“10.20.0.0/16”" in (event.detail or "")
        assert "scan host cap" in (event.detail or "")
