"""Device history and scan comparison, built from records that already exist.

Nothing here measures anything. Every event on a timeline is a row some other
part of the application wrote when it did something: a scan observation, a
diagnostic result, an action execution, an operator change. This module only
puts them in order and says what differs between consecutive observations.

That constraint is what keeps the history trustworthy. Between two scans
nothing is known, so nothing is shown — no interpolated status, no assumed
uptime. A port that a scan did not check is "not checked", never "closed".
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    ActionExecution,
    ChangeEvent,
    Device,
    DiagnosticResult,
    DiscoveryObservation,
    DiscoveryRun,
)
from app.modules.diagnostics import service as diagnostics_service
from app.modules.history.changes import CHANGE_LABELS

Tone = Literal["ok", "warn", "err", "info"]

# Per-source cap when assembling a timeline. Each source is indexed on
# (device_id, time), so this bounds the work per page view regardless of how
# much history a long-lived device has accumulated.
SOURCE_LIMIT = 100

# Fields compared between two observations, with the label shown to the operator.
COMPARED_FIELDS: tuple[tuple[str, str], ...] = (
    ("ip_address", "IP address"),
    ("mac_address", "MAC address"),
    ("hostname", "Hostname"),
    ("vendor", "Vendor"),
)


def as_utc(value: datetime) -> datetime:
    """SQLite returns naive datetimes even for timezone-aware columns.

    Mixing naive and aware values in one sort raises, so everything is
    normalised before it is merged.
    """
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


# ---------------------------------------------------------------------------
# Comparing two observations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldChange:
    label: str
    before: str | None
    after: str | None

    def describe(self) -> str:
        before = self.before or "not reported"
        after = self.after or "not reported"
        return f"{self.label}: {before} → {after}"


@dataclass(frozen=True)
class ObservationDiff:
    fields: list[FieldChange] = field(default_factory=list)
    opened: list[str] = field(default_factory=list)
    closed: list[str] = field(default_factory=list)
    # False when either side did not check ports. The UI must then say ports
    # were not compared, rather than implying they were and nothing moved.
    ports_compared: bool = True

    @property
    def changed(self) -> bool:
        return bool(self.fields or self.opened or self.closed)

    def lines(self) -> list[str]:
        result = [change.describe() for change in self.fields]
        if self.opened:
            result.append("Newly open: " + ", ".join(self.opened))
        if self.closed:
            result.append("No longer open: " + ", ".join(self.closed))
        return result


def port_labels(ports: Sequence[dict[str, Any]] | None) -> dict[str, str]:
    """``{"22/tcp": "22/tcp (ssh)"}`` — keyed by what identifies a port."""
    labels: dict[str, str] = {}
    for entry in ports or []:
        key = f"{entry.get('port')}/{entry.get('protocol', 'tcp')}"
        service = entry.get("service")
        labels[key] = f"{key} ({service})" if service else key
    return labels


def _port_sort_key(label: str) -> tuple[str, int]:
    """Order ``"22/tcp (ssh)"`` by protocol, then numerically by port.

    Only the protocol token is compared, not the rest of the label: including
    the service name sorted 443 (https) ahead of 22 (ssh).
    """
    number, _, rest = label.partition("/")
    protocol = rest.split(" ", 1)[0]
    return (protocol, int(number) if number.isdigit() else 0)


def diff_observations(before: DiscoveryObservation, after: DiscoveryObservation) -> ObservationDiff:
    """What differs between two observations of the same device.

    Both are expected to be *present* observations. An absent observation
    carries the device's last known values rather than anything the scan saw,
    so comparing against one would invent changes.
    """
    changes = [
        FieldChange(label, getattr(before, name), getattr(after, name))
        for name, label in COMPARED_FIELDS
        if (getattr(before, name) or None) != (getattr(after, name) or None)
    ]

    if before.ports is None or after.ports is None:
        return ObservationDiff(fields=changes, ports_compared=False)

    old = port_labels(before.ports)
    new = port_labels(after.ports)
    return ObservationDiff(
        fields=changes,
        opened=sorted((new[key] for key in new.keys() - old.keys()), key=_port_sort_key),
        closed=sorted((old[key] for key in old.keys() - new.keys()), key=_port_sort_key),
    )


def describe_ports(ports: Sequence[dict[str, Any]] | None) -> str:
    if ports is None:
        return "ports not checked"
    if not ports:
        return "no open ports found"
    return "open: " + ", ".join(sorted(port_labels(ports).values(), key=_port_sort_key))


# ---------------------------------------------------------------------------
# Device timeline
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimelineEvent:
    when: datetime
    category: Literal["scan", "change", "diagnostic", "action", "inventory"]
    title: str
    tone: Tone = "info"
    details: list[str] = field(default_factory=list)
    actor: str | None = None
    link: str | None = None


@dataclass(frozen=True)
class ScanCoverage:
    """How often scans have looked at this device, and how often it answered."""

    scans: int
    answered: int
    last_run_id: int | None
    last_present: bool | None


@dataclass(frozen=True)
class DeviceTimeline:
    events: list[TimelineEvent]
    coverage: ScanCoverage
    truncated: bool


_STATUS_TONE: dict[str, Tone] = {
    "success": "ok",
    "failed": "err",
    "timeout": "warn",
    "rejected": "warn",
    "busy": "warn",
    "running": "info",
}


def scan_events(
    observations: Sequence[DiscoveryObservation], runs: dict[int, DiscoveryRun]
) -> tuple[list[TimelineEvent], ScanCoverage]:
    """Turn a device's observations, oldest first, into the events worth reading.

    Only transitions are reported: first sighting, a change between two
    sightings, going quiet, and answering again. A scan that saw exactly what
    the previous one saw is counted in the coverage figures but adds no row —
    otherwise a device scanned daily would bury its one real change under a
    year of "no change".
    """
    events: list[TimelineEvent] = []
    last_present: DiscoveryObservation | None = None
    previous: DiscoveryObservation | None = None
    answered = 0

    for observation in observations:
        run = runs.get(observation.run_id)
        actor = run.username_snapshot if run else None
        scope = f"scan #{observation.run_id}" + (f" of {run.subnet}" if run else "")
        link = f"/discovery/runs/{observation.run_id}/report"
        when = as_utc(observation.observed_at)

        if not observation.present:
            # Report going quiet once, not on every scan it stays quiet for.
            if previous is None or previous.present:
                events.append(
                    TimelineEvent(
                        when=when,
                        category="scan",
                        title=f"Did not answer {scope}",
                        tone="warn",
                        details=[
                            "A known device inside the scanned range that did not respond. "
                            "It may be powered off, asleep, on a new address, or filtering probes."
                        ],
                        actor=actor,
                        link=link,
                    )
                )
            previous = observation
            continue

        answered += 1
        if last_present is None:
            events.append(
                TimelineEvent(
                    when=when,
                    category="scan",
                    title=f"First recorded by {scope}",
                    tone="ok",
                    details=[
                        f"IP address {observation.ip_address}",
                        f"MAC address {observation.mac_address or 'not visible (routed)'}",
                        f"Hostname {observation.hostname or 'not reported'}",
                        describe_ports(observation.ports).capitalize(),
                    ],
                    actor=actor,
                    link=link,
                )
            )
        else:
            diff = diff_observations(last_present, observation)
            returned = previous is not None and not previous.present
            if returned or diff.changed:
                details = diff.lines()
                if not diff.ports_compared and (last_present.ports or observation.ports):
                    details.append("Ports not compared: one of the two scans did not check them.")
                if returned and not diff.changed:
                    details.append("Nothing differs from when it was last seen.")
                events.append(
                    TimelineEvent(
                        when=when,
                        category="scan",
                        title=(f"Answered again in {scope}" if returned else f"Changed in {scope}"),
                        tone="ok" if returned else "info",
                        details=details,
                        actor=actor,
                        link=link,
                    )
                )
        last_present = observation
        previous = observation

    last = observations[-1] if observations else None
    coverage = ScanCoverage(
        scans=len(observations),
        answered=answered,
        last_run_id=last.run_id if last else None,
        last_present=last.present if last else None,
    )
    return events, coverage


def _diagnostic_event(result: DiagnosticResult) -> TimelineEvent:
    spec = diagnostics_service.REGISTRY.get(result.type)
    label = spec.label if spec else result.type
    return TimelineEvent(
        when=as_utc(result.started_at),
        category="diagnostic",
        title=f"{label}: {diagnostics_service.result_summary(result)}",
        tone=_STATUS_TONE.get(result.status, "info"),
        details=[f"Target {result.target}"],
        actor=result.username_snapshot,
        link=f"/diagnostics/{result.id}",
    )


def _action_event(execution: ActionExecution) -> TimelineEvent:
    return TimelineEvent(
        when=as_utc(execution.started_at),
        category="action",
        title=f"Action “{execution.action_name_snapshot or 'unknown'}”: {execution.status}",
        tone=_STATUS_TONE.get(execution.status, "info"),
        # Already redacted when it was written.
        details=[execution.command_preview] if execution.command_preview else [],
        actor=execution.username_snapshot,
    )


def _change_event(event: ChangeEvent) -> TimelineEvent:
    details = [event.detail] if event.detail else []
    if event.subject and event.kind.startswith(("host_key", "credential")):
        details.insert(0, event.subject)
    return TimelineEvent(
        when=as_utc(event.created_at),
        category="change",
        title=CHANGE_LABELS.get(event.kind, event.kind),
        tone="warn" if event.kind in ("host_key_revoked", "device_removed") else "info",
        details=details,
        actor=event.username_snapshot,
    )


async def device_timeline(
    session: AsyncSession, device: Device, *, limit: int = 200
) -> DeviceTimeline:
    observations = list(
        await session.scalars(
            select(DiscoveryObservation)
            .where(DiscoveryObservation.device_id == device.id)
            .order_by(DiscoveryObservation.observed_at.desc(), DiscoveryObservation.id.desc())
            .limit(SOURCE_LIMIT)
        )
    )
    observations.reverse()

    run_ids = {observation.run_id for observation in observations}
    runs = (
        {
            run.id: run
            for run in await session.scalars(
                select(DiscoveryRun).where(DiscoveryRun.id.in_(run_ids))
            )
        }
        if run_ids
        else {}
    )

    events, coverage = scan_events(observations, runs)

    events.append(
        TimelineEvent(
            when=as_utc(device.first_seen),
            category="inventory",
            title="Added to the inventory",
            details=["The first time any scan found this device."],
        )
    )

    diagnostics = await session.scalars(
        select(DiagnosticResult)
        .where(DiagnosticResult.device_id == device.id)
        .order_by(DiagnosticResult.started_at.desc())
        .limit(SOURCE_LIMIT)
    )
    events += [_diagnostic_event(result) for result in diagnostics]

    executions = await session.scalars(
        select(ActionExecution)
        .where(ActionExecution.device_id == device.id)
        .order_by(ActionExecution.started_at.desc())
        .limit(SOURCE_LIMIT)
    )
    events += [_action_event(execution) for execution in executions]

    changes = await session.scalars(
        select(ChangeEvent)
        .where(ChangeEvent.device_id == device.id)
        .order_by(ChangeEvent.created_at.desc())
        .limit(SOURCE_LIMIT)
    )
    events += [_change_event(event) for event in changes]

    events.sort(key=lambda event: event.when, reverse=True)
    return DeviceTimeline(events=events[:limit], coverage=coverage, truncated=len(events) > limit)


# ---------------------------------------------------------------------------
# Comparing two scans
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostDelta:
    device_id: int | None
    label: str
    ip_address: str
    lines: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RunComparison:
    base: DiscoveryRun
    target: DiscoveryRun
    added: list[HostDelta]
    missing: list[HostDelta]
    outside: list[HostDelta]
    changed: list[HostDelta]
    unchanged: int
    ports_compared: bool
    notes: list[str]
    comparable: bool


def has_host_results(run: DiscoveryRun, observation_count: int) -> bool:
    return run.status == "success" and observation_count > 0


def _key(observation: DiscoveryObservation) -> str:
    # Identity was already resolved when the scan was reconciled; reuse it.
    if observation.device_id is not None:
        return f"device:{observation.device_id}"
    return f"ip:{observation.ip_address}"


def _in_network(address: str, subnet: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


def why_no_host_results(run: DiscoveryRun) -> str:
    if run.status != "success":
        return f"Scan #{run.id} ended with status “{run.status}”, so it has no per-host results."
    if run.scanned_ports is None:
        return (
            f"Scan #{run.id} was recorded before per-host scan history existed, "
            "so only its summary counts are available."
        )
    return f"Scan #{run.id} found no hosts."


async def run_observations(session: AsyncSession, run_id: int) -> list[DiscoveryObservation]:
    return list(
        await session.scalars(
            select(DiscoveryObservation)
            .where(DiscoveryObservation.run_id == run_id)
            .order_by(DiscoveryObservation.id)
        )
    )


async def device_labels(session: AsyncSession, device_ids: set[int]) -> dict[int, str]:
    if not device_ids:
        return {}
    rows = await session.execute(
        select(Device.id, Device.name, Device.hostname, Device.ip_address).where(
            Device.id.in_(device_ids)
        )
    )
    return {row.id: row.name or row.hostname or row.ip_address for row in rows}


async def compare_runs(
    session: AsyncSession, base: DiscoveryRun, target: DiscoveryRun
) -> RunComparison:
    """What the later scan saw differently from the earlier one.

    Hosts are matched by the device identity resolved at scan time (MAC first,
    then address), so a device that moved address shows as *changed* rather
    than as one host missing and another added.
    """
    base_rows = await run_observations(session, base.id)
    target_rows = await run_observations(session, target.id)

    notes: list[str] = []
    comparable = True
    for run, rows in ((base, base_rows), (target, target_rows)):
        if not has_host_results(run, len(rows)):
            notes.append(why_no_host_results(run))
            comparable = False

    if base.subnet != target.subnet:
        notes.append(
            f"The scans covered different ranges ({base.subnet} and {target.subnet}). "
            "Hosts outside the later scan's range are listed separately, not as missing."
        )

    ports_compared = bool(base.scanned_ports and target.scanned_ports)
    if comparable and not ports_compared:
        notes.append("Ports are not compared: at least one of the scans did not check them.")

    before = {_key(row): row for row in base_rows if row.present}
    after = {_key(row): row for row in target_rows if row.present}

    labels = await device_labels(
        session,
        {row.device_id for row in (*before.values(), *after.values()) if row.device_id},
    )

    def delta(row: DiscoveryObservation, lines: list[str] | None = None) -> HostDelta:
        label = labels.get(row.device_id or -1) or row.hostname or row.ip_address
        return HostDelta(row.device_id, label, row.ip_address, lines or [])

    added = [
        delta(row, [describe_ports(row.ports)]) for key, row in after.items() if key not in before
    ]
    missing: list[HostDelta] = []
    outside: list[HostDelta] = []
    for key, row in before.items():
        if key in after:
            continue
        if _in_network(row.ip_address, target.subnet):
            missing.append(delta(row))
        else:
            outside.append(delta(row))

    changed: list[HostDelta] = []
    unchanged = 0
    for key in before.keys() & after.keys():
        diff = diff_observations(before[key], after[key])
        if not ports_compared:
            diff = ObservationDiff(fields=diff.fields, ports_compared=False)
        if diff.changed:
            changed.append(delta(after[key], diff.lines()))
        else:
            unchanged += 1

    def by_address(item: HostDelta) -> tuple[int, ...]:
        try:
            return tuple(ipaddress.ip_address(item.ip_address).packed)
        except ValueError:  # pragma: no cover - addresses were validated at scan time
            return (255,)

    for bucket in (added, missing, outside, changed):
        bucket.sort(key=by_address)

    return RunComparison(
        base=base,
        target=target,
        added=added if comparable else [],
        missing=missing if comparable else [],
        outside=outside if comparable else [],
        changed=changed if comparable else [],
        unchanged=unchanged if comparable else 0,
        ports_compared=ports_compared,
        notes=notes,
        comparable=comparable,
    )


async def previous_comparable_run(session: AsyncSession, run: DiscoveryRun) -> DiscoveryRun | None:
    """The most recent earlier successful scan of the same range with host results."""
    return await session.scalar(
        select(DiscoveryRun)
        .where(
            DiscoveryRun.subnet == run.subnet,
            DiscoveryRun.status == "success",
            DiscoveryRun.id < run.id,
            DiscoveryRun.id.in_(select(DiscoveryObservation.run_id).distinct()),
        )
        .order_by(DiscoveryRun.id.desc())
        .limit(1)
    )


async def runs_with_results(session: AsyncSession, limit: int = 50) -> list[DiscoveryRun]:
    return list(
        await session.scalars(
            select(DiscoveryRun)
            .where(
                DiscoveryRun.status == "success",
                DiscoveryRun.id.in_(select(DiscoveryObservation.run_id).distinct()),
            )
            .order_by(DiscoveryRun.id.desc())
            .limit(limit)
        )
    )
