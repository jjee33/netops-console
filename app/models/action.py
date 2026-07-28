"""Admin-defined actions and their execution history.

The distinction that governs this whole feature: a *diagnostic* is hardcoded and
therefore safe by construction, while an *action* is defined by an administrator
and is only as safe as the validation around it. Everything here exists to make
that validation unavoidable.

The browser never sends a command. It sends an action id and parameters; the
server resolves what actually runs. That is the property the API shape is chosen
to guarantee — there is no field anywhere that could carry a command string.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

EXECUTION_TYPES = ("local", "ssh")
EXECUTION_STATUSES = ("running", "success", "failed", "timeout", "rejected", "busy")

_STATUSES_SQL = ", ".join(f"'{name}'" for name in EXECUTION_STATUSES)


class ActionDefinition(Base):
    __tablename__ = "action_definition"
    __table_args__ = (
        CheckConstraint("execution_type IN ('local','ssh')", name="ck_action_execution_type"),
        CheckConstraint("timeout_seconds > 0", name="ck_action_timeout_positive"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    execution_type: Mapped[str] = mapped_column(String(8), nullable=False, default="local")

    # A list of argv tokens. Placeholders are written {name} and are substituted
    # one-for-one — a placeholder is always exactly one argv element, never
    # spliced into a longer string.
    argv_template: Mapped[list[str]] = mapped_column(JSON, nullable=False)

    # {name: {type, pattern, min, max, choices, required, secret}}. For SSH
    # actions a pattern is mandatory, because argv is not a boundary there.
    param_schema: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    # Makes the UI ask before running. For anything that changes state on a
    # device, an accidental click should not be enough.
    confirmation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Documents that the action depends on a sudoers entry the operator has to
    # install themselves. This application cannot grant itself privilege.
    elevated_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Empty means every device. Otherwise the action is only offered on devices
    # whose type matches, so a switch command is not one click away on a NAS.
    applicable_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ActionDefinition {self.id} {self.name!r} {self.execution_type}>"


class ActionExecution(Base):
    """Audit record for one run of an action.

    Same shape and the same reasoning as ``diagnostic_result``: nullable foreign
    keys with denormalised labels beside them, so deleting a device, an operator
    or the action definition itself cannot erase the record that it ran.
    """

    __tablename__ = "action_execution"
    __table_args__ = (
        CheckConstraint(f"status IN ({_STATUSES_SQL})", name="ck_action_execution_status"),
        Index("ix_action_execution_device_started", "device_id", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("device.id", ondelete="SET NULL"), nullable=True
    )
    action_definition_id: Mapped[int | None] = mapped_column(
        ForeignKey("action_definition.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    device_label_snapshot: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action_name_snapshot: Mapped[str | None] = mapped_column(String(128), nullable=True)
    username_snapshot: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Anything the schema flagged `secret` is masked before this is written.
    params_redacted: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # What was actually run, after substitution and redaction. The single most
    # useful field when working out what an action did.
    command_preview: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ActionExecution {self.id} {self.action_name_snapshot!r} {self.status}>"
