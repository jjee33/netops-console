"""Device identity and re-scan behaviour.

The requirement is that a scan is safely repeatable: running it twice must not
produce two copies of every device. These tests cover the cases where a naive
implementation gets that wrong.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import func, select

from app.core.db import get_session_factory
from app.models import Device, DevicePort
from app.modules.discovery.parser import ParsedHost, ParsedPort, ParsedScan, parse_scan
from app.modules.discovery.service import build_scan_arguments, reconcile, upsert_device

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def host(ip: str, mac: str | None = None, **kwargs: object) -> ParsedHost:
    return ParsedHost(ip_address=ip, mac_address=mac, **kwargs)  # type: ignore[arg-type]


class TestRescanIsSafe:
    async def test_scanning_the_same_range_twice_creates_no_duplicates(
        self, migrated: Path
    ) -> None:
        scan = parse_scan((FIXTURES / "nmap_typical.xml").read_text())

        async with get_session_factory()() as session:
            found, created = await reconcile(session, scan)
            assert (found, created) == (3, 3)

            found, created = await reconcile(session, scan)
            assert (found, created) == (3, 0), "a repeat scan created devices"

            total = await session.scalar(select(func.count()).select_from(Device))
            assert total == 3

    async def test_ports_are_not_duplicated_on_rescan(self, migrated: Path) -> None:
        scan = parse_scan((FIXTURES / "nmap_typical.xml").read_text())

        async with get_session_factory()() as session:
            await reconcile(session, scan)
            first = await session.scalar(select(func.count()).select_from(DevicePort))
            await reconcile(session, scan)
            second = await session.scalar(select(func.count()).select_from(DevicePort))

        assert first == second


class TestIdentity:
    async def test_a_device_that_changed_address_stays_one_device(self, migrated: Path) -> None:
        """DHCP reassignment is routine. Keying on the address alone would make
        every lease change look like a new device."""
        async with get_session_factory()() as session:
            device, is_new = await upsert_device(session, host("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
            await session.commit()
            assert is_new
            original_id = device.id

            device, is_new = await upsert_device(session, host("10.0.0.99", "aa:bb:cc:dd:ee:ff"))
            await session.commit()

            assert is_new is False
            assert device.id == original_id
            assert device.ip_address == "10.0.0.99"

    async def test_two_devices_sharing_an_address_over_time_stay_distinct(
        self, migrated: Path
    ) -> None:
        """A returned lease handed to a different machine is a different device,
        and merging them would corrupt its history."""
        async with get_session_factory()() as session:
            first, _ = await upsert_device(session, host("10.0.0.5", "aa:aa:aa:aa:aa:aa"))
            await session.commit()

            second, is_new = await upsert_device(session, host("10.0.0.5", "bb:bb:bb:bb:bb:bb"))
            await session.commit()

            assert is_new is True
            assert second.id != first.id

    async def test_a_routed_device_without_a_mac_is_matched_by_address(
        self, migrated: Path
    ) -> None:
        async with get_session_factory()() as session:
            first, _ = await upsert_device(session, host("10.0.0.50"))
            await session.commit()

            again, is_new = await upsert_device(session, host("10.0.0.50"))
            await session.commit()

            assert is_new is False
            assert again.id == first.id

    async def test_a_device_first_seen_without_a_mac_adopts_one_later(self, migrated: Path) -> None:
        """A host discovered across a router, then later scanned from its own
        segment, is the same device — not a second one."""
        async with get_session_factory()() as session:
            first, _ = await upsert_device(session, host("10.0.0.50"))
            await session.commit()
            assert first.mac_address is None

            same, is_new = await upsert_device(session, host("10.0.0.50", "aa:bb:cc:00:11:22"))
            await session.commit()

            assert is_new is False
            assert same.id == first.id
            assert same.mac_address == "aa:bb:cc:00:11:22"

            total = await session.scalar(select(func.count()).select_from(Device))
            assert total == 1


class TestFieldMerging:
    async def test_an_operator_assigned_name_survives_rediscovery(self, migrated: Path) -> None:
        """Discovery must never overwrite something a human typed."""
        async with get_session_factory()() as session:
            device, _ = await upsert_device(session, host("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
            device.name = "Core switch"
            device.notes = "Rack 2"
            await session.commit()

            await upsert_device(
                session,
                host("10.0.0.5", "aa:bb:cc:dd:ee:ff", hostname="autodiscovered.lan"),
            )
            await session.commit()
            await session.refresh(device)

            assert device.name == "Core switch"
            assert device.notes == "Rack 2"
            assert device.hostname == "autodiscovered.lan"

    async def test_vendor_is_not_cleared_by_a_scan_that_did_not_see_it(
        self, migrated: Path
    ) -> None:
        async with get_session_factory()() as session:
            device, _ = await upsert_device(
                session, host("10.0.0.5", "aa:bb:cc:dd:ee:ff", vendor="Ubiquiti Inc")
            )
            await session.commit()

            await upsert_device(session, host("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
            await session.commit()
            await session.refresh(device)

            assert device.vendor == "Ubiquiti Inc"

    async def test_a_soft_deleted_device_is_restored_not_duplicated(self, migrated: Path) -> None:
        """Otherwise deleting a device and rescanning leaves two records, one of
        them holding the audit history."""
        async with get_session_factory()() as session:
            device, _ = await upsert_device(session, host("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
            device.is_deleted = True
            await session.commit()
            original_id = device.id

            restored, is_new = await upsert_device(session, host("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
            await session.commit()

            assert is_new is False
            assert restored.id == original_id
            assert restored.is_deleted is False
            assert await session.scalar(select(func.count()).select_from(Device)) == 1


class TestPortSync:
    async def test_ports_are_recorded_and_updated(self, migrated: Path) -> None:
        async with get_session_factory()() as session:
            observation = host("10.0.0.5", "aa:bb:cc:dd:ee:ff")
            observation.ports = [ParsedPort(22, "tcp", "open", "ssh")]
            device, _ = await upsert_device(session, observation)
            await session.commit()

            changed = host("10.0.0.5", "aa:bb:cc:dd:ee:ff")
            changed.ports = [ParsedPort(22, "tcp", "filtered", "ssh")]
            await upsert_device(session, changed)
            await session.commit()

            ports = (
                await session.scalars(select(DevicePort).where(DevicePort.device_id == device.id))
            ).all()

            assert len(ports) == 1
            assert ports[0].state == "filtered"

    async def test_a_scan_that_saw_no_ports_does_not_erase_known_ones(self, migrated: Path) -> None:
        """A single scan missing a port is far likelier than the service having
        been removed. Losing history every scan would make this useless."""
        async with get_session_factory()() as session:
            observation = host("10.0.0.5", "aa:bb:cc:dd:ee:ff")
            observation.ports = [ParsedPort(22, "tcp", "open", "ssh")]
            device, _ = await upsert_device(session, observation)
            await session.commit()

            await upsert_device(session, host("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
            await session.commit()

            remaining = await session.scalar(
                select(func.count())
                .select_from(DevicePort)
                .where(DevicePort.device_id == device.id)
            )
            assert remaining == 1


class TestDownHosts:
    async def test_hosts_that_did_not_answer_are_not_added(self, migrated: Path) -> None:
        scan = ParsedScan(
            hosts=[host("10.0.0.5", "aa:bb:cc:dd:ee:ff"), host("10.0.0.9", is_up=False)]
        )
        async with get_session_factory()() as session:
            found, created = await reconcile(session, scan)

        assert (found, created) == (1, 1)


class TestScanArguments:
    def test_no_shell_metacharacters_reach_the_argument_list(self) -> None:
        arguments = build_scan_arguments("10.0.0.0/24")
        assert all(isinstance(argument, str) for argument in arguments)
        assert arguments[-1] == "10.0.0.0/24"

    def test_output_goes_to_stdout_not_a_file(self) -> None:
        """No temp file means no path handling, and no path handling means no
        path traversal to reason about."""
        arguments = build_scan_arguments("10.0.0.0/24")
        assert "-oX" in arguments
        assert arguments[arguments.index("-oX") + 1] == "-"

    def test_host_discovery_only_mode_skips_the_port_scan(self) -> None:
        arguments = build_scan_arguments("10.0.0.0/24", with_ports=False)
        assert "-sn" in arguments
        assert "-sS" not in arguments

    def test_a_host_timeout_is_always_present(self) -> None:
        arguments = build_scan_arguments("10.0.0.0/24")
        assert "--host-timeout" in arguments
