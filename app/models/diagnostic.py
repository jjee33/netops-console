"""Diagnostic results — the audit record for everything run against a device.

Written alongside the diagnostics feature rather than after it. Retrofitting an
audit trail onto commands that already run is the shortcut that becomes
permanent, and the same reasoning applies here as to SSH host key verification:
build the accountable path first, or the unaccountable one ships.

Both foreign keys are ``ON DELETE SET NULL`` with a denormalised label beside
them. Deleting a device or an operator must not erase the record that something
was run — that record is the point.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

DIAGNOSTIC_TYPES = (
    "ping",
    "traceroute",
    "dns",
    "rdns",
    "tcp",
    "service_scan",
    "arp",
    "http_check",
)

DIAGNOSTIC_STATUSES = ("success", "failed", "timeout", "rejected", "busy")

_TYPES_SQL = ", ".join(f"'{name}'" for name in DIAGNOSTIC_TYPES)
_STATUSES_SQL = ", ".join(f"'{name}'" for name in DIAGNOSTIC_STATUSES)


class DiagnosticResult(Base):
    __tablename__ = "diagnostic_result"
    __table_args__ = (
        CheckConstraint(f"type IN ({_TYPES_SQL})", name="ck_diagnostic_type"),
        CheckConstraint(f"status IN ({_STATUSES_SQL})", name="ck_diagnostic_status"),
        # The audit view and the per-device history both read newest-first.
        Index("ix_diagnostic_device_started", "device_id", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("device.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    # Denormalised so a row stays readable after whatever it referred to is gone.
    device_label_snapshot: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username_snapshot: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    type: Mapped[str] = mapped_column(String(16), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)

    # Already redacted when written. Nothing flagged secret reaches this column.
    params_redacted: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    status: Mapped[str] = mapped_column(String(16), nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Parsed out of the output where the diagnostic produces them, so the
    # device page can show a latency trend without re-parsing stored text.
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_pct: Mapped[float | None] = mapped_column(Float, nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    @property
    def succeeded(self) -> bool:
        return self.status == "success"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<DiagnosticResult {self.id} {self.type} {self.target} {self.status}>"
