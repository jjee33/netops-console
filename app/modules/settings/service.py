"""Reading and writing operator-editable settings.

Defaults come from the environment on first read and are then persisted, so a
fresh install is usable immediately but subsequent changes are made in the UI
and survive a container replacement.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.validation import ValidationError, validate_allowed_cidr
from app.models import Setting

KEY_ALLOWED_CIDRS: Final = "allowed_cidrs"
KEY_MAX_SCAN_HOSTS: Final = "max_scan_hosts"
KEY_MAX_CONCURRENT_SCANS: Final = "max_concurrent_scans"
KEY_MAX_CONCURRENT_EXECUTIONS: Final = "max_concurrent_executions"
KEY_RETENTION_DAYS: Final = "retention_days"
KEY_STRICT_HOST_KEYS: Final = "strict_host_keys"

# Bounds that exist to stop an operator disabling a safety control by typing a
# large number into a form. The scan cap in particular is what keeps a
# mistyped prefix from turning into a multi-hour scan of 16 million addresses.
MAX_SCAN_HOSTS_CEILING: Final = 65536
MAX_CONCURRENCY_CEILING: Final = 16
MAX_RETENTION_DAYS: Final = 3650


@dataclass
class AppSettings:
    allowed_cidrs: list[str]
    max_scan_hosts: int
    max_concurrent_scans: int
    max_concurrent_executions: int
    retention_days: int
    strict_host_keys: bool

    @property
    def allowed_networks(self) -> list[ipaddress.IPv4Network]:
        return [ipaddress.IPv4Network(cidr) for cidr in self.allowed_cidrs]


async def _get_raw(session: AsyncSession) -> dict[str, Any]:
    rows = (await session.scalars(select(Setting))).all()
    return {row.key: row.value for row in rows}


async def load(session: AsyncSession) -> AppSettings:
    stored = await _get_raw(session)
    env = get_settings()

    return AppSettings(
        allowed_cidrs=stored.get(KEY_ALLOWED_CIDRS, env.allowed_cidrs),
        max_scan_hosts=stored.get(KEY_MAX_SCAN_HOSTS, env.max_scan_hosts),
        max_concurrent_scans=stored.get(KEY_MAX_CONCURRENT_SCANS, env.max_concurrent_scans),
        max_concurrent_executions=stored.get(
            KEY_MAX_CONCURRENT_EXECUTIONS, env.max_concurrent_executions
        ),
        retention_days=stored.get(KEY_RETENTION_DAYS, env.retention_days),
        strict_host_keys=stored.get(KEY_STRICT_HOST_KEYS, True),
    )


async def _put(session: AsyncSession, key: str, value: Any) -> None:
    existing = await session.get(Setting, key)
    if existing is None:
        session.add(Setting(key=key, value=value))
    else:
        existing.value = value


def parse_cidr_list(raw: str) -> list[str]:
    """Parse the settings form's textarea into a validated list.

    Every entry is validated; the first failure aborts the whole save. A
    partially applied allowlist is worse than a rejected one, because the
    operator would believe a range is covered when it is not.
    """
    entries = [line.strip() for line in raw.replace(",", "\n").splitlines()]
    entries = [entry for entry in entries if entry]

    if not entries:
        raise ValidationError("At least one allowed range is required.")

    seen: dict[str, None] = {}
    for entry in entries:
        network = validate_allowed_cidr(entry)
        seen[str(network)] = None

    return list(seen)


def _bounded_int(raw: str, *, label: str, minimum: int, maximum: int) -> int:
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{label} must be a whole number.") from exc
    if not minimum <= value <= maximum:
        raise ValidationError(f"{label} must be between {minimum} and {maximum}.")
    return value


async def save(
    session: AsyncSession,
    *,
    allowed_cidrs_raw: str,
    max_scan_hosts: str,
    max_concurrent_scans: str,
    max_concurrent_executions: str,
    retention_days: str,
    strict_host_keys: bool,
) -> AppSettings:
    """Validate and persist the whole settings form as one unit."""
    cidrs = parse_cidr_list(allowed_cidrs_raw)
    scan_hosts = _bounded_int(
        max_scan_hosts, label="Maximum scan hosts", minimum=1, maximum=MAX_SCAN_HOSTS_CEILING
    )
    concurrent_scans = _bounded_int(
        max_concurrent_scans,
        label="Concurrent scans",
        minimum=1,
        maximum=MAX_CONCURRENCY_CEILING,
    )
    concurrent_executions = _bounded_int(
        max_concurrent_executions,
        label="Concurrent executions",
        minimum=1,
        maximum=MAX_CONCURRENCY_CEILING,
    )
    retention = _bounded_int(
        retention_days, label="Retention days", minimum=1, maximum=MAX_RETENTION_DAYS
    )

    await _put(session, KEY_ALLOWED_CIDRS, cidrs)
    await _put(session, KEY_MAX_SCAN_HOSTS, scan_hosts)
    await _put(session, KEY_MAX_CONCURRENT_SCANS, concurrent_scans)
    await _put(session, KEY_MAX_CONCURRENT_EXECUTIONS, concurrent_executions)
    await _put(session, KEY_RETENTION_DAYS, retention)
    await _put(session, KEY_STRICT_HOST_KEYS, bool(strict_host_keys))
    await session.commit()

    return await load(session)
