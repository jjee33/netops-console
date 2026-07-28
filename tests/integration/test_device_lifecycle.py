"""Device status lifecycle and startup reconciliation.

Both cover the same class of bug: state that is only ever written in the happy
direction. A device was set online and never anything else, so the dashboard's
Offline tile read zero forever; a run was set running and only cleared by the
task that a restart had already killed.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from app.core.db import get_session_factory
from app.models import Device, DiscoveryRun
from app.modules.discovery.parser import ParsedHost, ParsedScan
from app.modules.discovery.service import (
    fail_interrupted_runs,
    mark_absent_devices_offline,
    reconcile,
    upsert_device,
)

NETWORK = ipaddress.IPv4Network("10.0.30.0/24")


def host(ip: str, mac: str | None = None) -> ParsedHost:
    return ParsedHost(ip_address=ip, mac_address=mac)


async def _seen_at(ip: str, when: datetime, mac: str | None = None) -> int:
    async with get_session_factory()() as session:
        device, _ = await upsert_device(session, host(ip, mac))
        device.last_seen = when
        device.status = "online"
        await session.commit()
        return device.id


async def _status(device_id: int) -> str:
    async with get_session_factory()() as session:
        device = await session.get(Device, device_id)
        assert device
        return device.status


class TestOfflineDetection:
    async def test_a_device_that_stops_answering_goes_offline(self, migrated: Path) -> None:
        """The bug this replaces: status was set to online on discovery and never
        changed, so a device gone for a month still read online."""
        old = datetime.now(UTC) - timedelta(days=2)
        device_id = await _seen_at("10.0.30.50", old)
        assert await _status(device_id) == "online"

        async with get_session_factory()() as session:
            await mark_absent_devices_offline(session, NETWORK, datetime.now(UTC))
            await session.commit()

        assert await _status(device_id) == "offline"

    async def test_a_device_that_answered_stays_online(self, migrated: Path) -> None:
        scanned_at = datetime.now(UTC)
        scan = ParsedScan(hosts=[host("10.0.30.50", "aa:bb:cc:dd:ee:ff")])

        async with get_session_factory()() as session:
            await reconcile(session, scan, NETWORK, scanned_at)
            device = await session.scalar(select(Device))

        assert device and device.status == "online"

    async def test_only_the_scanned_range_is_affected(self, migrated: Path) -> None:
        """A device on a subnet nobody scanned has not been shown to be absent.
        Marking it offline would be a guess presented as a fact."""
        old = datetime.now(UTC) - timedelta(days=2)
        inside = await _seen_at("10.0.30.50", old)
        elsewhere = await _seen_at("10.0.99.50", old, mac="11:22:33:44:55:66")

        async with get_session_factory()() as session:
            await mark_absent_devices_offline(session, NETWORK, datetime.now(UTC))
            await session.commit()

        assert await _status(inside) == "offline"
        assert await _status(elsewhere) == "online"

    async def test_a_full_scan_marks_the_absent_and_keeps_the_present(self, migrated: Path) -> None:
        old = datetime.now(UTC) - timedelta(hours=6)
        present = await _seen_at("10.0.30.10", old, mac="aa:aa:aa:aa:aa:aa")
        absent = await _seen_at("10.0.30.20", old, mac="bb:bb:bb:bb:bb:bb")

        scanned_at = datetime.now(UTC)
        scan = ParsedScan(hosts=[host("10.0.30.10", "aa:aa:aa:aa:aa:aa")])

        async with get_session_factory()() as session:
            await reconcile(session, scan, NETWORK, scanned_at)

        assert await _status(present) == "online"
        assert await _status(absent) == "offline"

    async def test_a_device_coming_back_returns_to_online(self, migrated: Path) -> None:
        device_id = await _seen_at("10.0.30.50", datetime.now(UTC) - timedelta(days=2))

        async with get_session_factory()() as session:
            await mark_absent_devices_offline(session, NETWORK, datetime.now(UTC))
            await session.commit()
        assert await _status(device_id) == "offline"

        async with get_session_factory()() as session:
            await reconcile(
                session,
                ParsedScan(hosts=[host("10.0.30.50")]),
                NETWORK,
                datetime.now(UTC),
            )
        assert await _status(device_id) == "online"

    async def test_soft_deleted_devices_are_left_alone(self, migrated: Path) -> None:
        device_id = await _seen_at("10.0.30.50", datetime.now(UTC) - timedelta(days=2))
        async with get_session_factory()() as session:
            device = await session.get(Device, device_id)
            assert device
            device.is_deleted = True
            await session.commit()

        async with get_session_factory()() as session:
            changed = await mark_absent_devices_offline(session, NETWORK, datetime.now(UTC))
            await session.commit()

        assert changed == 0

    async def test_reconcile_without_a_network_marks_nothing(self, migrated: Path) -> None:
        """The two-argument form is used where absence cannot be inferred."""
        device_id = await _seen_at("10.0.30.50", datetime.now(UTC) - timedelta(days=2))
        async with get_session_factory()() as session:
            await reconcile(session, ParsedScan(hosts=[]))
        assert await _status(device_id) == "online"


class TestInterruptedRuns:
    async def test_a_stranded_run_is_closed(self, migrated: Path) -> None:
        """Otherwise the Discovery page polls a spinner forever and the
        application looks hung when it is simply showing a dead scan."""
        async with get_session_factory()() as session:
            session.add(DiscoveryRun(subnet="10.0.30.0/24", status="running"))
            await session.commit()

        async with get_session_factory()() as session:
            assert await fail_interrupted_runs(session) == 1

        async with get_session_factory()() as session:
            run = await session.scalar(select(DiscoveryRun))
            assert run
            assert run.status == "failed"
            assert run.completed_at is not None
            assert "restarted" in (run.output_summary or "")

    async def test_finished_runs_are_untouched(self, migrated: Path) -> None:
        async with get_session_factory()() as session:
            session.add(
                DiscoveryRun(
                    subnet="10.0.30.0/24",
                    status="success",
                    devices_found=4,
                    output_summary="4 host(s) responded; 1 new.",
                )
            )
            await session.commit()

        async with get_session_factory()() as session:
            assert await fail_interrupted_runs(session) == 0

        async with get_session_factory()() as session:
            run = await session.scalar(select(DiscoveryRun))
            assert run and run.status == "success"
            assert run.output_summary == "4 host(s) responded; 1 new."

    async def test_it_is_a_no_op_on_a_clean_database(self, migrated: Path) -> None:
        async with get_session_factory()() as session:
            assert await fail_interrupted_runs(session) == 0
