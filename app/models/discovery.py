"""Discovery run history.

A scan is an auditable action, not a background detail: it touches every host
in a range and the record of who started it matters. ``user_id`` is nullable
and set to NULL on user deletion so history survives, with a text snapshot
alongside it for the same reason.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

RUN_STATUSES = ("running", "success", "failed", "timeout", "rejected")


class DiscoveryRun(Base):
    __tablename__ = "discovery_run"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running','success','failed','timeout','rejected')",
            name="ck_discovery_run_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subnet: Mapped[str] = mapped_column(String(45), nullable=False)

    # SET NULL rather than CASCADE: deleting an operator must not erase the
    # record that a scan happened.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    # Denormalised so the row stays readable after the user row is gone.
    username_snapshot: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    devices_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_new: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<DiscoveryRun {self.id} {self.subnet} {self.status}>"
