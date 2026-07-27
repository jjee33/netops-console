"""Device inventory.

Identity is the hard part here. A device on a DHCP network has no stable
identifier that is always present: the MAC is stable but invisible across a
router, the IP is always visible but reassigned, and modern clients randomise
their MAC per network. The compromise is MAC-first with IP fallback, plus
manual merge — documented on :func:`app.modules.discovery.service.upsert_device`.

Deletion is soft. Hard-deleting would either cascade away the device's audit
history, which the whole point of this application is to keep, or fail on a
foreign key constraint.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

DEVICE_STATUSES = ("online", "offline", "unknown", "warning")
PORT_PROTOCOLS = ("tcp", "udp")
PORT_STATES = ("open", "filtered", "closed")


class Device(Base):
    __tablename__ = "device"
    __table_args__ = (
        CheckConstraint(
            "status IN ('online','offline','unknown','warning')", name="ck_device_status"
        ),
        Index("ix_device_status_deleted", "status", "is_deleted"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Operator-assigned label. Survives rediscovery; the discovered hostname
    # does not overwrite it.
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Deliberately NOT unique. DHCP reassigns addresses, and a unique
    # constraint here turns a normal lease change into a failed scan.
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)

    # Null for anything discovered across a router — the MAC is simply not
    # visible at layer 3, which is not an error.
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    avg_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    ports: Mapped[list[DevicePort]] = relationship(
        back_populates="device", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def display_name(self) -> str:
        return self.name or self.hostname or self.ip_address

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Device {self.id} {self.ip_address} {self.mac_address}>"


class DevicePort(Base):
    __tablename__ = "device_port"
    __table_args__ = (
        UniqueConstraint("device_id", "port", "protocol", name="uq_device_port"),
        CheckConstraint("protocol IN ('tcp','udp')", name="ck_port_protocol"),
        CheckConstraint("state IN ('open','filtered','closed')", name="ck_port_state"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("device.id", ondelete="CASCADE"), nullable=False, index=True
    )

    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(3), nullable=False, default="tcp")
    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(8), nullable=False, default="open")

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    device: Mapped[Device] = relationship(back_populates="ports")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<DevicePort {self.port}/{self.protocol} {self.state}>"
