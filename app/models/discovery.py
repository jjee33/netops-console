"""Discovery run history.

A scan is an auditable action, not a background detail: it touches every host
in a range and the record of who started it matters. ``user_id`` is nullable
and set to NULL on user deletion so history survives, with a text snapshot
alongside it for the same reason.
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
    # Whether this run checked ports. Port differences between two runs are
    # only meaningful when both did. None means the run predates the column.
    scanned_ports: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    output_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<DiscoveryRun {self.id} {self.subnet} {self.status}>"


class DiscoveryObservation(Base):
    """What one scan saw of one device — or that it did not see it.

    The device row holds only the latest state; every scan overwrites it. This
    table is what makes "what changed, and when" answerable afterwards, and it
    records only what nmap actually returned. Nothing here is inferred, sampled
    or synthesised between scans: a device that was not scanned has no row.

    ``present`` is False for a known device inside the scanned range that did
    not answer. That is the same inference
    :func:`app.modules.discovery.service.mark_absent_devices_offline` makes, and
    is recorded so the timeline can say *which* scan it was based on.

    ``ports`` is None when the run did not check ports (or the device was
    absent), which is different from an empty list: "not looked at" must never
    read as "all closed".
    """

    __tablename__ = "discovery_observation"
    __table_args__ = (
        Index("ix_observation_device_observed", "device_id", "observed_at"),
        Index("ix_observation_run", "run_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # CASCADE: an observation means nothing without the run that produced it.
    run_id: Mapped[int] = mapped_column(
        ForeignKey("discovery_run.id", ondelete="CASCADE"), nullable=False
    )
    # SET NULL, like every other history table: the record outlives the device.
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("device.id", ondelete="SET NULL"), nullable=True
    )

    present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # [{"port": 22, "protocol": "tcp", "service": "ssh"}, ...], sorted.
    ports: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)

    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "present" if self.present else "absent"
        return f"<DiscoveryObservation run={self.run_id} device={self.device_id} {state}>"
