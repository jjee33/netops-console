"""Running diagnostics and recording what was run.

Every path through this module writes a :class:`DiagnosticResult`, including the
ones that fail and the ones that are refused before anything runs. A refusal is
as much a thing that happened as a success, and an audit log that only records
successes is not an audit log.

Targets are re-validated here against the *current* settings rather than trusted
because discovery found them. Allowed ranges can be narrowed after a device is
in the inventory, and a device row is not a permission.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.execution import ExecutionBusy, ExecutionRejected, ExecutionStatus, get_engine
from app.core.redaction import sanitize
from app.core.validation import (
    ValidationError,
    address_in_allowlist,
    is_blocked,
    parse_ipv4,
    validate_hostname,
    validate_port,
)
from app.models import DiagnosticResult
from app.models.device import Device
from app.modules.diagnostics import builders, http_check
from app.modules.diagnostics.parsers import parse_ping, summarise_ping

logger = logging.getLogger("netops.diagnostics")


@dataclass(frozen=True)
class DiagnosticSpec:
    """What a diagnostic is called, and what it needs."""

    key: str
    label: str
    description: str
    # Shown on the button; the operator should know what will happen.
    detail: str
    needs_port: bool = False
    confirm: bool = False


REGISTRY: Final[dict[str, DiagnosticSpec]] = {
    "ping": DiagnosticSpec(
        "ping", "Ping", "ICMP reachability and latency", "Sends 4 echo requests."
    ),
    "traceroute": DiagnosticSpec(
        "traceroute", "Traceroute", "Path to the device", "Up to 15 hops, one probe each."
    ),
    "dns": DiagnosticSpec(
        "dns", "DNS lookup", "Forward lookup of the hostname", "Queries this host's resolver."
    ),
    "rdns": DiagnosticSpec(
        "rdns", "Reverse DNS", "PTR record for the address", "Queries this host's resolver."
    ),
    "tcp": DiagnosticSpec(
        "tcp", "TCP port test", "Connect to a single port", "Plain connect, no probing.",
        needs_port=True,
    ),
    "service_scan": DiagnosticSpec(
        "service_scan", "Service scan", "Identify services on common ports",
        "Slowest option — probes ten ports for version banners.", confirm=True,
    ),
    "arp": DiagnosticSpec(
        "arp", "ARP entry", "Neighbour table entry", "Reads the cache; sends nothing."
    ),
    "http_check": DiagnosticSpec(
        "http_check", "HTTP check", "Fetch the device's web interface",
        "One GET, redirects not followed, certificates not verified.", needs_port=True,
    ),
}  # fmt: skip

# How much output to keep per result. Smaller than the engine's own cap because
# these rows accumulate and each one carries its blob into every backup.
MAX_STORED_OUTPUT: Final = 32 * 1024


def validate_device_target(
    device: Device, allowed: list[ipaddress.IPv4Network]
) -> ipaddress.IPv4Address:
    """Confirm a device is still somewhere we are permitted to reach.

    Re-checked at execution time. A device discovered when 10.0.0.0/8 was
    allowed must stop being contactable if that range is later removed —
    otherwise the inventory becomes a way to keep reaching hosts the operator
    has since put out of scope.
    """
    address = parse_ipv4(device.ip_address)

    if is_blocked(address):
        raise ValidationError(f"{address} is in a reserved range and cannot be contacted.")
    if not address_in_allowlist(address, allowed):
        raise ValidationError(
            f"{address} is outside the currently allowed ranges. "
            f"Add its range in Settings if you intend to manage it."
        )
    return address


async def run_diagnostic(
    session: AsyncSession,
    device: Device,
    kind: str,
    allowed: list[ipaddress.IPv4Network],
    *,
    user_id: int | None,
    username: str | None,
    client_ip: str | None,
    port: int | None = None,
    count: int | None = None,
) -> DiagnosticResult:
    """Run a built-in diagnostic against a device and record the outcome."""
    if kind not in REGISTRY:
        # Not user-facing under normal use; the UI offers a fixed set.
        raise ValidationError(f"{kind!r} is not a known diagnostic.")

    started = datetime.now(UTC)
    result = DiagnosticResult(
        device_id=device.id,
        user_id=user_id,
        device_label_snapshot=device.display_name,
        username_snapshot=username,
        client_ip=client_ip,
        type=kind,
        target=device.ip_address,
        params_redacted={
            key: value for key, value in (("port", port), ("count", count)) if value is not None
        },
        status="rejected",
        started_at=started,
    )

    try:
        address = validate_device_target(device, allowed)
    except ValidationError as exc:
        return await _finish(session, result, "rejected", str(exc), started)

    try:
        if kind == "http_check":
            return await _run_http(session, result, device, address, port, allowed, started)
        return await _run_command(session, result, kind, address, device, port, count, started)
    except ValidationError as exc:
        return await _finish(session, result, "rejected", str(exc), started)
    except ExecutionBusy as exc:
        return await _finish(session, result, "busy", str(exc), started)
    except ExecutionRejected as exc:
        logger.error("diagnostic %s refused: %s", kind, exc)
        return await _finish(session, result, "rejected", str(exc), started)


async def _run_command(
    session: AsyncSession,
    result: DiagnosticResult,
    kind: str,
    address: ipaddress.IPv4Address,
    device: Device,
    port: int | None,
    count: int | None,
    started: datetime,
) -> DiagnosticResult:
    target = str(address)

    builder_map: dict[str, Callable[[], builders.Command]] = {
        "ping": lambda: builders.ping(target, count),
        "traceroute": lambda: builders.traceroute(target, count),
        "rdns": lambda: builders.reverse_dns(target),
        "service_scan": lambda: builders.service_scan(target),
        "arp": lambda: builders.arp_neighbour(target),
        "tcp": lambda: builders.tcp_check(target, _require_port(port)),
    }

    if kind == "dns":
        # The only diagnostic whose subject is the name rather than the address.
        if not device.hostname:
            raise ValidationError(
                "This device has no discovered hostname, so there is nothing to look up. "
                "Try a reverse DNS lookup instead."
            )
        command = builders.dns_lookup(validate_hostname(device.hostname))
        result.target = device.hostname
    else:
        command = builder_map[kind]()

    execution = await get_engine().run(command.program, command.arguments, timeout=command.timeout)

    combined = execution.stdout
    if execution.stderr.strip():
        combined = f"{combined}\n--- stderr ---\n{execution.stderr}".strip()

    if execution.status is ExecutionStatus.TIMEOUT:
        return await _finish(
            session,
            result,
            "timeout",
            combined or "The command exceeded its time limit.",
            started,
            exit_code=execution.exit_code,
        )

    latency = loss = None
    if kind == "ping":
        latency, loss = parse_ping(execution.stdout)
        await _update_device_latency(device, latency, loss)

    # A non-zero exit is a real answer — an unreachable host is information, not
    # a malfunction — so it is recorded as failed rather than discarded.
    status = "success" if execution.status is ExecutionStatus.SUCCESS else "failed"

    return await _finish(
        session,
        result,
        status,
        combined or "(no output)",
        started,
        exit_code=execution.exit_code,
        latency_ms=latency,
        packet_loss_pct=loss,
    )


async def _run_http(
    session: AsyncSession,
    result: DiagnosticResult,
    device: Device,
    address: ipaddress.IPv4Address,
    port: int | None,
    allowed: list[ipaddress.IPv4Network],
    started: datetime,
) -> DiagnosticResult:
    checked_port = _require_port(port)
    scheme = "https" if checked_port in (443, 8443) else "http"

    outcome = await http_check.check(str(address), checked_port, scheme, allowed)
    result.target = f"{scheme}://{address}:{checked_port}"

    return await _finish(
        session,
        result,
        "success" if outcome.ok else "failed",
        outcome.detail,
        started,
        latency_ms=outcome.latency_ms,
        summary=outcome.summary,
    )


def _require_port(port: int | None) -> int:
    if port is None:
        raise ValidationError("This diagnostic needs a port.")
    return validate_port(port)


async def _update_device_latency(device: Device, latency: float | None, loss: float | None) -> None:
    """Keep a rolling latency figure and the reachability status current.

    A ping is the cheapest possible statement about whether a device is up, so
    it is worth letting one correct the inventory — a device that answers is
    online whatever the last scan concluded.
    """
    if latency is not None:
        previous = device.avg_latency_ms
        # Exponential moving average: one slow reply should nudge the figure,
        # not replace it.
        device.avg_latency_ms = (
            latency if previous is None else round(previous * 0.7 + latency * 0.3, 3)
        )

    if loss is not None:
        if loss >= 100:
            device.status = "offline"
        else:
            device.status = "online"
            device.last_seen = datetime.now(UTC)


async def _finish(
    session: AsyncSession,
    result: DiagnosticResult,
    status: str,
    output: str,
    started: datetime,
    *,
    exit_code: int | None = None,
    latency_ms: float | None = None,
    packet_loss_pct: float | None = None,
    summary: str | None = None,
) -> DiagnosticResult:
    completed = datetime.now(UTC)

    # Sanitised again on the way in. The engine already did this for command
    # output, but the HTTP path does not pass through it, and a second pass on
    # already-clean text costs nothing.
    clean, _ = sanitize(output, max_bytes=MAX_STORED_OUTPUT)

    result.status = status
    result.output = clean
    result.exit_code = exit_code
    result.latency_ms = latency_ms
    result.packet_loss_pct = packet_loss_pct
    result.completed_at = completed
    result.duration_ms = int((completed - started).total_seconds() * 1000)

    session.add(result)
    await session.commit()

    logger.info(
        "diagnostic %s on %s: %s (%dms)",
        result.type,
        result.target,
        status,
        result.duration_ms or 0,
    )
    return result


def result_summary(result: DiagnosticResult) -> str:
    """One line describing the outcome, for the result header."""
    if result.type == "ping" and result.status in ("success", "failed"):
        return summarise_ping(result.latency_ms, result.packet_loss_pct)
    return {
        "success": "Completed",
        "failed": "Failed",
        "timeout": "Timed out",
        "rejected": "Refused",
        "busy": "Busy",
    }.get(result.status, result.status)


async def recent_for_device(
    session: AsyncSession, device_id: int, limit: int = 10
) -> list[DiagnosticResult]:
    return list(
        await session.scalars(
            select(DiagnosticResult)
            .where(DiagnosticResult.device_id == device_id)
            .order_by(DiagnosticResult.started_at.desc())
            .limit(limit)
        )
    )


async def prune(session: AsyncSession, retention_days: int) -> int:
    """Prune execution history. Delegates to the shared retention module.

    Kept as a thin wrapper because this is the call site that matters — the
    path that creates the volume is the one that pays for cleaning it up — but
    the policy itself now covers action executions too, which accumulate the
    same way and were previously never pruned at all.
    """
    from app.core.retention import prune as prune_all

    return (await prune_all(session, retention_days)).total


__all__ = [
    "REGISTRY",
    "DiagnosticSpec",
    "prune",
    "recent_for_device",
    "result_summary",
    "run_diagnostic",
    "validate_device_target",
]
