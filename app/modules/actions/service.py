"""Defining and running actions.

Two execution paths with genuinely different security properties.

**Local.** argv arrays, no shell. A parameter containing shell metacharacters is
passed to the program as one literal string, so validation is defence in depth
rather than the only thing standing between a parameter and execution.

**SSH.** sshd receives a single command string and hands it to the target user's
login shell. Argv discipline buys nothing there. What protects the target is, in
order: the mandatory per-parameter pattern, ``shlex.quote`` on every substituted
value, and — the only one that survives a compromise of *this* application — an
``authorized_keys`` ``command="..."`` restriction on the device itself.

An SSH action will not run against a device whose host key has not been
explicitly trusted by a human. That check happens before the credential is
decrypted, let alone offered.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.execution import ExecutionBusy, ExecutionRejected, ExecutionStatus, get_engine
from app.core.validation import ValidationError, address_in_allowlist, is_blocked, parse_ipv4
from app.models import ActionDefinition, ActionExecution, Device
from app.modules.actions import schema

logger = logging.getLogger("netops.actions")

MAX_TIMEOUT_SECONDS = 300


async def list_definitions(
    session: AsyncSession, *, enabled_only: bool = False
) -> list[ActionDefinition]:
    statement = select(ActionDefinition).order_by(ActionDefinition.name)
    if enabled_only:
        statement = statement.where(ActionDefinition.enabled.is_(True))
    return list(await session.scalars(statement))


def applicable_to(definition: ActionDefinition, device: Device) -> bool:
    """Whether an action should be offered on a device.

    An empty type list means every device. Otherwise the action only appears on
    matching devices, so a switch command is not one click away on a NAS.
    """
    if not definition.applicable_types:
        return True
    return (device.device_type or "").strip().lower() in {
        entry.strip().lower() for entry in definition.applicable_types
    }


async def actions_for_device(session: AsyncSession, device: Device) -> list[ActionDefinition]:
    return [
        definition
        for definition in await list_definitions(session, enabled_only=True)
        if applicable_to(definition, device)
    ]


def validate_definition(
    *,
    name: str,
    execution_type: str,
    argv_template: list[str],
    param_schema: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, schema.ParamSpec]:
    """Validate a definition before it is stored.

    Everything checkable is checked here rather than at run time, so an unsafe
    or unrunnable action cannot be saved and then discovered later by whoever
    clicks it.
    """
    if not name.strip():
        raise ValidationError("The action needs a name.")
    if len(name) > 128:
        raise ValidationError("The name is too long.")
    if execution_type not in ("local", "ssh"):
        raise ValidationError("Execution type must be 'local' or 'ssh'.")
    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValidationError(f"Timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds.")

    specs = schema.parse_schema(param_schema, execution_type=execution_type)
    schema.validate_template(argv_template, specs, execution_type=execution_type)
    return specs


def _validate_target(device: Device, allowed: list[ipaddress.IPv4Network]) -> None:
    """Same rule as diagnostics: a device row is not a permission."""
    address = parse_ipv4(device.ip_address)
    if is_blocked(address):
        raise ValidationError(f"{address} is in a reserved range and cannot be contacted.")
    if not address_in_allowlist(address, allowed):
        raise ValidationError(
            f"{address} is outside the currently allowed ranges. "
            f"Add its range in Settings if you intend to manage it."
        )


async def execute(
    session: AsyncSession,
    definition: ActionDefinition,
    device: Device,
    values: dict[str, Any],
    allowed: list[ipaddress.IPv4Network],
    *,
    user_id: int | None,
    username: str | None,
    client_ip: str | None,
) -> ActionExecution:
    """Run an action against a device, recording the attempt either way."""
    started = datetime.now(UTC)

    execution = ActionExecution(
        device_id=device.id,
        action_definition_id=definition.id,
        user_id=user_id,
        device_label_snapshot=device.display_name,
        action_name_snapshot=definition.name,
        username_snapshot=username,
        client_ip=client_ip,
        status="rejected",
        started_at=started,
    )

    try:
        specs = schema.parse_schema(
            definition.param_schema, execution_type=definition.execution_type
        )
        execution.params_redacted = schema.redact(values, specs)

        if not definition.enabled:
            raise ValidationError("This action is disabled.")
        if not applicable_to(definition, device):
            raise ValidationError(
                f"This action does not apply to devices of type {device.device_type or 'unset'!r}."
            )

        _validate_target(device, allowed)

        if definition.execution_type == "ssh":
            return await _execute_ssh(
                session, execution, definition, device, specs, values, started
            )

        argv = schema.build_argv(definition.argv_template, specs, values)

    except ValidationError as exc:
        return await _finish(session, execution, "rejected", stderr=str(exc), started=started)

    # Stored before running: the single most useful field for working out what
    # an action actually did, and it must survive the command failing.
    execution.command_preview = " ".join(argv)

    try:
        result = await get_engine().run(
            argv[0], argv[1:], timeout=float(definition.timeout_seconds)
        )
    except ExecutionBusy as exc:
        return await _finish(session, execution, "busy", stderr=str(exc), started=started)
    except ExecutionRejected as exc:
        logger.error("action %r refused: %s", definition.name, exc)
        return await _finish(session, execution, "rejected", stderr=str(exc), started=started)

    status = {
        ExecutionStatus.SUCCESS: "success",
        ExecutionStatus.TIMEOUT: "timeout",
    }.get(result.status, "failed")

    return await _finish(
        session,
        execution,
        status,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        started=started,
    )


async def _execute_ssh(
    session: AsyncSession,
    execution: ActionExecution,
    definition: ActionDefinition,
    device: Device,
    specs: dict[str, schema.ParamSpec],
    values: dict[str, Any],
    started: datetime,
) -> ActionExecution:
    """Run an action over SSH, refusing anything unverified.

    Order matters here and is the point of the function: host key first, then
    credential, then command. A device we cannot identify never sees a key.
    """
    from app.modules.credentials import service as credentials_service
    from app.modules.ssh import client as ssh_client

    credentials = await credentials_service.for_device(session, device.id)
    if not credentials:
        return await _finish(
            session,
            execution,
            "rejected",
            stderr=(
                "No credential is assigned to this device. Assign one on the device "
                "page before running SSH actions against it."
            ),
            started=started,
        )
    credential = credentials[0]

    trusted = await credentials_service.trusted_key_for(session, device.id)

    # Built after the checks above so a rejected run still records what would
    # have been sent, with secrets already masked.
    command = schema.build_ssh_command(definition.argv_template, specs, values)
    execution.command_preview = command

    try:
        result = await ssh_client.run_command(
            device.ip_address,
            command,
            username=credential.username,
            auth_type=credential.auth_type,
            secret_ciphertext=credential.secret_ciphertext,
            passphrase_ciphertext=credential.passphrase_ciphertext,
            trusted_key=trusted,
            timeout=float(definition.timeout_seconds),
        )
    except ssh_client.UnknownHostKey as exc:
        logger.warning("ssh action refused: unverified host key for device %s", device.id)
        return await _finish(session, execution, "rejected", stderr=str(exc), started=started)
    except ssh_client.HostKeyChanged as exc:
        logger.error("ssh action refused: host key changed for device %s", device.id)
        return await _finish(session, execution, "rejected", stderr=str(exc), started=started)
    except ssh_client.SshError as exc:
        return await _finish(session, execution, "failed", stderr=str(exc), started=started)

    credential.last_used_at = datetime.now(UTC)

    return await _finish(
        session,
        execution,
        "success" if result.exit_status == 0 else "failed",
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_status,
        started=started,
    )


async def _finish(
    session: AsyncSession,
    execution: ActionExecution,
    status: str,
    *,
    started: datetime,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
) -> ActionExecution:
    completed = datetime.now(UTC)

    execution.status = status
    execution.stdout = stdout or None
    execution.stderr = stderr or None
    execution.exit_code = exit_code
    execution.completed_at = completed
    execution.duration_ms = int((completed - started).total_seconds() * 1000)

    session.add(execution)
    await session.commit()

    logger.info(
        "action %r on %s: %s",
        execution.action_name_snapshot,
        execution.device_label_snapshot,
        status,
    )
    return execution


async def recent_for_device(
    session: AsyncSession, device_id: int, limit: int = 10
) -> list[ActionExecution]:
    return list(
        await session.scalars(
            select(ActionExecution)
            .where(ActionExecution.device_id == device_id)
            .order_by(ActionExecution.started_at.desc())
            .limit(limit)
        )
    )
