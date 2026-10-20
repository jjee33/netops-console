"""Operator changes to inventory, trust and configuration.

Diagnostics, actions and scans each have their own history table because each
carries output. Everything else an administrator does — renaming or removing a
device, trusting or forgetting a host key, assigning a credential, changing the
allowed ranges — previously went only to the process log, which does not
survive a container being recreated and is not visible in the audit view.

Forgetting a host key is the sharpest case: it deletes the row that recorded who
trusted the key, so without this table the act of revoking trust erased the
evidence that trust had ever been granted.

Same shape as the other history tables: nullable foreign keys with denormalised
snapshots, so the record outlives the device, the account and the subject. No
secret is ever written here — a credential appears by name only.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

CHANGE_KINDS = (
    "device_edited",
    "device_removed",
    "host_key_trusted",
    "host_key_revoked",
    "credential_created",
    "credential_deleted",
    "credential_assigned",
    "credential_unassigned",
    "action_created",
    "action_enabled",
    "action_disabled",
    "action_deleted",
    "settings_changed",
)

_KINDS_SQL = ", ".join(f"'{name}'" for name in CHANGE_KINDS)


class ChangeEvent(Base):
    __tablename__ = "change_event"
    __table_args__ = (
        CheckConstraint(f"kind IN ({_KINDS_SQL})", name="ck_change_event_kind"),
        Index("ix_change_event_device_created", "device_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Set in Python rather than by the database: CURRENT_TIMESTAMP has
    # one-second resolution, which is too coarse to order events that one
    # request writes back to back.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    kind: Mapped[str] = mapped_column(String(32), nullable=False)

    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("device.id", ondelete="SET NULL"), nullable=True
    )
    device_label_snapshot: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # What was changed, by name: a credential, an action, a key fingerprint.
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Human-readable description of the change. Operator-entered values may
    # appear here, so it is rendered escaped like everything else.
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    username_snapshot: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ChangeEvent {self.id} {self.kind} device={self.device_id}>"
