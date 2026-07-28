"""Credentials and SSH host key trust.

Two tables that only make sense together: what we present to a device, and what
we require the device to present back.

Nothing here ever stores a secret in the clear, and nothing here is ever sent to
a browser. The UI shows a name, a username and a fingerprint — enough to tell
two credentials apart, and nothing that would help use one.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

AUTH_TYPES = ("ssh_key", "password")


class Credential(Base):
    __tablename__ = "credential"
    __table_args__ = (
        CheckConstraint("auth_type IN ('ssh_key','password')", name="ck_credential_auth_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    username: Mapped[str] = mapped_column(String(64), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(16), nullable=False, default="ssh_key")

    # Fernet ciphertext of the private key or password. There is deliberately no
    # column, property or route that exposes the plaintext — it is decrypted in
    # memory at connection time and nowhere else.
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Passphrase for an encrypted private key, itself encrypted.
    passphrase_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Public, and the only identifying detail shown in the UI.
    key_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        # Never includes ciphertext, even in a debugger.
        return f"<Credential {self.id} {self.name!r} {self.username}@{self.auth_type}>"


class DeviceCredential(Base):
    """Which credential to use for which device."""

    __tablename__ = "device_credential"
    __table_args__ = (UniqueConstraint("device_id", "credential_id", name="uq_device_credential"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("device.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[int] = mapped_column(
        ForeignKey("credential.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class SshHostKey(Base):
    """A host key an operator has explicitly chosen to trust.

    Stored in the database rather than a ``known_hosts`` file for two reasons:
    the container root filesystem is read-only, and a trust decision is exactly
    the kind of thing that should be attributable and reviewable rather than
    appended to a file by a process.

    Trust on first use, with the emphasis on *use* — nothing is trusted
    automatically. The first connection surfaces the fingerprint and stops; a
    human decides. A key that later changes fails the connection rather than
    being silently re-trusted, because a changed host key is either a rebuilt
    device or a machine-in-the-middle, and only the operator knows which.
    """

    __tablename__ = "ssh_host_key"
    __table_args__ = (
        UniqueConstraint("device_id", "key_type", name="uq_host_key_device_type"),
        Index("ix_ssh_host_key_device", "device_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("device.id", ondelete="CASCADE"), nullable=False
    )

    key_type: Mapped[str] = mapped_column(String(32), nullable=False)
    key_base64: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    trusted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # Who accepted it. SET NULL so removing an operator does not erase the
    # record that a trust decision was made.
    trusted_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    trusted_by_snapshot: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SshHostKey device={self.device_id} {self.key_type} {self.fingerprint}>"
