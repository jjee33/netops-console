"""Recording operator changes.

One helper so every call site writes the same shape, and so a new kind of
change cannot be recorded without also being added to ``CHANGE_KINDS`` — the
check constraint rejects anything else.

The helper adds the row to the session and does not commit; the calling route
commits it. Where the route makes the change itself (device edits and removal,
action and settings changes, credential deletion), the event and the change
share one transaction. Where a service function commits the change first
(credential creation and assignment, host key trust and revocation), the event
follows in a second commit immediately after. A crash between the two would
leave the change without its record. The window is a single statement, and it
is stated here rather than claimed away.

Every call happens only after the change succeeded. A request that fails
validation renders an error, and the session dependency still commits at the
end of the request, so recording first would log changes that never happened.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core.requests import client_ip
from app.models import ChangeEvent, Device, User
from app.models.change import CHANGE_KINDS

# How each kind reads in the audit log and on a device timeline.
CHANGE_LABELS: dict[str, str] = {
    "device_edited": "Device details edited",
    "device_removed": "Removed from the inventory",
    "host_key_trusted": "SSH host key trusted",
    "host_key_revoked": "SSH host key forgotten",
    "credential_created": "Credential added",
    "credential_deleted": "Credential deleted",
    "credential_assigned": "Credential assigned",
    "credential_unassigned": "Credential unassigned",
    "action_created": "Action defined",
    "action_enabled": "Action enabled",
    "action_disabled": "Action disabled",
    "action_deleted": "Action deleted",
    "settings_changed": "Settings changed",
}

# Long free text (device notes, mostly) is summarised rather than copied: the
# change log says *that* it changed, and the device page holds the value.
MAX_VALUE_CHARS = 80


def record_change(
    session: AsyncSession,
    request: Request,
    user: User,
    kind: str,
    *,
    device: Device | None = None,
    subject: str | None = None,
    detail: str | None = None,
) -> ChangeEvent:
    if kind not in CHANGE_KINDS:
        raise ValueError(f"unknown change kind {kind!r}")

    event = ChangeEvent(
        created_at=datetime.now(UTC),
        kind=kind,
        device_id=device.id if device else None,
        device_label_snapshot=device.display_name if device else None,
        subject=subject[:255] if subject else None,
        detail=detail,
        user_id=user.id,
        username_snapshot=user.username,
        client_ip=client_ip(request),
    )
    session.add(event)
    return event


def describe_value(value: object) -> str:
    """Render one field value for a change description."""
    if value is None or value == "":
        return "(empty)"
    text = str(value)
    if len(text) > MAX_VALUE_CHARS:
        text = text[: MAX_VALUE_CHARS - 1] + "…"
    return f"“{text}”"


def describe_changes(
    before: Mapping[str, object], after: Mapping[str, object], *, summarise: tuple[str, ...] = ()
) -> str | None:
    """``name: “a” → “b”; notes changed`` — or None when nothing changed.

    Fields named in ``summarise`` are reported as changed without their values.
    """
    parts: list[str] = []
    for field, old in before.items():
        new = after.get(field)
        if old == new:
            continue
        if field in summarise:
            parts.append(f"{field} changed")
        else:
            parts.append(f"{field}: {describe_value(old)} → {describe_value(new)}")
    return "; ".join(parts) if parts else None
