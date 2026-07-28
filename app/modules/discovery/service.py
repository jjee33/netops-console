"""Running scans and reconciling the results into the inventory.

The identity problem is the substance of this module. A scan produces a set of
observations; turning them into stable device records is where naive
implementations create duplicates on every run.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.execution import ExecutionBusy, ExecutionRejected, ExecutionStatus, get_engine
from app.core.validation import ValidationError, validate_scan_target
from app.models import Device, DevicePort, DiscoveryRun
from app.modules.discovery.parser import ParsedHost, ParsedScan, ScanParseError, parse_scan

logger = logging.getLogger("netops.discovery")

# Ports worth knowing about on a management network, kept short so a scan of a
# /24 finishes in seconds rather than minutes. Not configurable in v0.1: the
# argv is built here, not supplied by a user.
DEFAULT_PORTS = "22,53,80,111,139,443,445,554,1883,3000,3389,5000,5432,8006,8080,8443,9000"

SCAN_TIMEOUT_SECONDS = 300.0

# Reading the container's own interfaces is cheap and must never delay the page.
INTERFACE_TIMEOUT_SECONDS = 5.0


def parse_local_networks(ip_output: str) -> list[ipaddress.IPv4Network]:
    """Extract the networks this host is attached to from ``ip -4 -o addr show``.

    Each line looks like::

        2: eth0  inet 10.0.10.5/24 brd 10.0.10.255 scope global eth0\\  valid_lft ...

    Only the address and prefix are used; everything else is ignored. Loopback
    is excluded because scanning ourselves is never the intent.
    """
    networks: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()

    for line in ip_output.splitlines():
        fields = line.split()
        if "inet" not in fields:
            continue
        try:
            value = fields[fields.index("inet") + 1]
        except IndexError:
            continue
        try:
            # strict=False: the interface address has host bits set by
            # definition, and the network it implies is what we want.
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if not isinstance(network, ipaddress.IPv4Network) or network.is_loopback:
            continue
        if str(network) not in seen:
            seen.add(str(network))
            networks.append(network)

    return networks


async def suggest_scan_targets(allowed: list[ipaddress.IPv4Network], max_hosts: int) -> list[str]:
    """Networks this container is attached to that are actually scannable.

    Exists because the alternative is asking an operator to type a subnet with
    no indication of which ones would be accepted — and the obvious guess, the
    first configured allowed range, is usually a supernet far above the host
    cap. Suggesting only ranges that pass both checks means anything offered
    here will work.

    Returns an empty list rather than raising: this is a convenience on a page
    that must still render if the lookup fails.
    """
    try:
        result = await get_engine().run(
            "ip", ["-4", "-o", "addr", "show"], timeout=INTERFACE_TIMEOUT_SECONDS
        )
    except (ExecutionBusy, ExecutionRejected) as exc:
        logger.debug("could not read local interfaces: %s", exc)
        return []

    if result.status is not ExecutionStatus.SUCCESS:
        logger.debug("`ip addr` exited %s", result.exit_code)
        return []

    suggestions: list[str] = []
    for network in parse_local_networks(result.stdout):
        if network.num_addresses > max_hosts:
            continue
        if not any(network.subnet_of(entry) for entry in allowed):
            continue
        suggestions.append(str(network))

    return suggestions


def build_scan_arguments(subnet: str, *, with_ports: bool = True) -> list[str]:
    """Build the nmap arguments for a discovery scan.

    Every element is a fixed token or a validated subnet — nothing here is
    assembled from user text. The caller has already checked the subnet against
    the allowlist and the host cap.
    """
    arguments = [
        "-oX",
        "-",  # XML to stdout; no temp files, so no path handling at all
        "-n",  # no DNS during the scan; reverse lookups happen separately
        "--host-timeout",
        "30s",
        "-T4",
    ]

    if with_ports:
        arguments += ["-sS", "-p", DEFAULT_PORTS, "--open"]
    else:
        arguments.append("-sn")  # host discovery only

    # Reverse DNS for the hosts that answered, which is much cheaper than
    # resolving every address in the range.
    arguments.append("-R")
    arguments.append(subnet)
    return arguments


async def create_run(
    session: AsyncSession,
    subnet: str,
    *,
    user_id: int | None,
    username: str | None,
    client_ip: str | None,
) -> DiscoveryRun:
    """Record that a scan was requested, before it starts.

    Written first so the run is visible while it is in progress and, more
    importantly, so a scan that crashes the process still left a trace that it
    was attempted and by whom.
    """
    run = DiscoveryRun(
        subnet=subnet,
        user_id=user_id,
        username_snapshot=username,
        client_ip=client_ip,
        status="running",
    )
    session.add(run)
    await session.commit()
    return run


async def mark_failed(session: AsyncSession, run: DiscoveryRun, summary: str) -> DiscoveryRun:
    return await _finish(session, run, "failed", summary=summary)


async def execute_run(
    session: AsyncSession,
    run: DiscoveryRun,
    subnet: str,
    allowed: list[ipaddress.IPv4Network],
    max_hosts: int,
    *,
    with_ports: bool = True,
) -> DiscoveryRun:
    """Scan, parse, and reconcile against an already-created run row."""
    try:
        network = validate_scan_target(subnet, allowed, max_hosts)
    except ValidationError as exc:
        # Re-checked here even though the route validated it: this function is
        # reachable from a background task and must not trust its caller.
        return await _finish(session, run, "rejected", summary=str(exc))

    run.subnet = str(network)

    try:
        result = await get_engine().run(
            "nmap",
            build_scan_arguments(str(network), with_ports=with_ports),
            timeout=SCAN_TIMEOUT_SECONDS,
            discovery=True,
        )
    except ExecutionBusy as exc:
        return await _finish(session, run, "rejected", summary=str(exc))
    except ExecutionRejected as exc:  # pragma: no cover - defensive
        logger.error("discovery refused: %s", exc)
        return await _finish(session, run, "failed", summary=str(exc))

    if result.status is ExecutionStatus.TIMEOUT:
        return await _finish(
            session, run, "timeout", summary=f"Scan exceeded {SCAN_TIMEOUT_SECONDS:.0f}s."
        )

    try:
        scan = parse_scan(result.stdout)
    except ScanParseError as exc:
        # A non-zero exit with unparseable output usually means a capability
        # problem, which is worth saying rather than reporting "parse failed".
        detail = result.stderr.strip() or str(exc)
        logger.error("discovery parse failed: %s", detail)
        return await _finish(session, run, "failed", summary=detail[:2000])

    found, created = await reconcile(session, scan)

    return await _finish(
        session,
        run,
        "success",
        summary=f"{found} host(s) responded; {created} new.",
        devices_found=found,
        devices_new=created,
        duration_ms=result.duration_ms,
    )


async def reconcile(session: AsyncSession, scan: ParsedScan) -> tuple[int, int]:
    """Merge scan results into the inventory. Returns (found, newly created)."""
    created = 0
    for host in scan.up_hosts:
        _, is_new = await upsert_device(session, host)
        if is_new:
            created += 1
    await session.commit()
    return len(scan.up_hosts), created


async def upsert_device(session: AsyncSession, host: ParsedHost) -> tuple[Device, bool]:
    """Find or create the device this observation belongs to.

    Matching order, and why:

    1. **MAC address**, when present. Stable across DHCP lease changes, so a
       device that moved address stays one device.
    2. **IP address**, otherwise. Everything across a router has no visible MAC,
       and the address is the only identifier available.

    Soft-deleted devices are matched too and revived rather than duplicated —
    otherwise deleting a device and rescanning silently creates a second copy
    of it alongside the original's audit history.

    Known limits, accepted for v0.1: a client using MAC randomisation appears as
    a new device each time it rotates, and two routed devices that swap
    addresses are indistinguishable. Both are resolved by manual merge, which is
    a post-MVP feature.
    """
    device: Device | None = None

    if host.mac_address:
        device = await session.scalar(select(Device).where(Device.mac_address == host.mac_address))

    if device is None:
        # Fall back to the address, but only against records that have no MAC
        # of their own. Two cases land here and both are handled correctly:
        #
        #  * the observation has no MAC (a routed device), so the address is the
        #    only identifier either side has;
        #  * the observation has a MAC that we have never seen, and an existing
        #    MAC-less record holds this address — that is the same device seen
        #    from layer 2 for the first time, so it adopts the MAC below rather
        #    than becoming a duplicate.
        #
        # A record that already has a *different* MAC is deliberately not
        # matched: a known device answering from this address would have been
        # found by the MAC lookup, so this is another host that took the lease.
        device = await session.scalar(
            select(Device).where(
                Device.ip_address == host.ip_address,
                Device.mac_address.is_(None),
            )
        )

    now = datetime.now(UTC)
    is_new = device is None

    if device is None:
        device = Device(
            ip_address=host.ip_address,
            mac_address=host.mac_address,
            first_seen=now,
        )
        session.add(device)

    device.ip_address = host.ip_address
    if host.mac_address:
        device.mac_address = host.mac_address
    if host.vendor:
        device.vendor = host.vendor
    if host.hostname:
        # Never overwrites `name`, which the operator set by hand.
        device.hostname = host.hostname

    device.status = "online"
    device.last_seen = now

    if device.is_deleted:
        device.is_deleted = False
        device.deleted_at = None
        logger.info("device %s reappeared in a scan and was restored", device.ip_address)

    await session.flush()
    await _sync_ports(session, device, host)

    return device, is_new


async def _sync_ports(session: AsyncSession, device: Device, host: ParsedHost) -> None:
    """Update the port list for a device.

    Ports that were not seen this time are left in place rather than deleted: a
    single scan missing a port is far more likely than the service having been
    removed, and losing history on every scan would make the inventory useless.
    """
    if not host.ports:
        return

    existing = {
        (port.port, port.protocol): port
        for port in await session.scalars(
            select(DevicePort).where(DevicePort.device_id == device.id)
        )
    }
    now = datetime.now(UTC)

    for parsed in host.ports:
        key = (parsed.port, parsed.protocol)
        current = existing.get(key)
        if current is None:
            session.add(
                DevicePort(
                    device_id=device.id,
                    port=parsed.port,
                    protocol=parsed.protocol,
                    state=parsed.state,
                    service=parsed.service,
                    last_seen=now,
                )
            )
        else:
            current.state = parsed.state
            if parsed.service:
                current.service = parsed.service
            current.last_seen = now


async def _finish(
    session: AsyncSession,
    run: DiscoveryRun,
    status: str,
    *,
    summary: str,
    devices_found: int = 0,
    devices_new: int = 0,
    duration_ms: int | None = None,
) -> DiscoveryRun:
    run.status = status
    run.output_summary = summary
    run.devices_found = devices_found
    run.devices_new = devices_new
    run.completed_at = datetime.now(UTC)
    run.duration_ms = duration_ms
    await session.commit()

    logger.info("discovery %s: %s — %s", run.id, status, summary)
    return run
