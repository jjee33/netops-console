"""Storing credentials and recording host key trust.

Nothing in this module returns a secret. Creation takes plaintext, encrypts it,
and forgets it; everything afterwards deals in ciphertext and metadata. The only
consumer of the plaintext is the SSH client at connection time.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import asyncssh
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt
from app.core.validation import ValidationError
from app.models import Credential, Device, DeviceCredential, SshHostKey
from app.modules.ssh import client as ssh_client

logger = logging.getLogger("netops.credentials")

MAX_SECRET_BYTES = 64 * 1024


def _inspect_private_key(material: str, passphrase: str | None) -> str:
    """Validate a private key and return a fingerprint of its public half.

    Parsed on the way in so a malformed or wrongly-passphrased key is rejected
    while the operator is looking at the form, rather than at 2am when an action
    fails against a device.
    """
    try:
        key = asyncssh.import_private_key(material, passphrase)
    except asyncssh.KeyEncryptionError as exc:
        raise ValidationError(
            "This key is passphrase protected and the passphrase is missing or wrong."
        ) from exc
    except asyncssh.KeyImportError as exc:
        raise ValidationError(
            "This does not look like a private key in a format we can read. "
            "OpenSSH and PEM formats are supported."
        ) from exc

    return key.get_fingerprint()


async def create(
    session: AsyncSession,
    *,
    name: str,
    username: str,
    auth_type: str,
    secret: str,
    passphrase: str | None = None,
    description: str | None = None,
) -> Credential:
    """Store a credential. The plaintext does not survive this call."""
    if not name.strip():
        raise ValidationError("The credential needs a name.")
    if not username.strip():
        raise ValidationError("The username is required.")
    if auth_type not in ("ssh_key", "password"):
        raise ValidationError("Authentication type must be 'ssh_key' or 'password'.")
    if not secret:
        raise ValidationError("The key or password is required.")
    if len(secret.encode()) > MAX_SECRET_BYTES:
        raise ValidationError("That secret is implausibly large.")

    existing = await session.scalar(select(Credential).where(Credential.name == name.strip()))
    if existing is not None:
        raise ValidationError(f"A credential named {name.strip()!r} already exists.")

    fingerprint: str | None = None
    if auth_type == "ssh_key":
        fingerprint = _inspect_private_key(secret, passphrase or None)

    credential = Credential(
        name=name.strip(),
        description=(description or "").strip() or None,
        username=username.strip(),
        auth_type=auth_type,
        secret_ciphertext=encrypt(secret),
        passphrase_ciphertext=encrypt(passphrase) if passphrase else None,
        key_fingerprint=fingerprint,
    )
    session.add(credential)
    await session.commit()

    logger.info("credential %r stored (%s)", credential.name, auth_type)
    return credential


async def list_all(session: AsyncSession) -> list[Credential]:
    return list(await session.scalars(select(Credential).order_by(Credential.name)))


async def assign(session: AsyncSession, device_id: int, credential_id: int) -> None:
    existing = await session.scalar(
        select(DeviceCredential).where(
            DeviceCredential.device_id == device_id,
            DeviceCredential.credential_id == credential_id,
        )
    )
    if existing is None:
        session.add(DeviceCredential(device_id=device_id, credential_id=credential_id))
        await session.commit()


async def unassign(session: AsyncSession, device_id: int, credential_id: int) -> None:
    existing = await session.scalar(
        select(DeviceCredential).where(
            DeviceCredential.device_id == device_id,
            DeviceCredential.credential_id == credential_id,
        )
    )
    if existing is not None:
        await session.delete(existing)
        await session.commit()


async def for_device(session: AsyncSession, device_id: int) -> list[Credential]:
    return list(
        await session.scalars(
            select(Credential)
            .join(DeviceCredential, DeviceCredential.credential_id == Credential.id)
            .where(DeviceCredential.device_id == device_id)
            .order_by(Credential.name)
        )
    )


# ---------------------------------------------------------------------------
# Host key trust
# ---------------------------------------------------------------------------


async def trusted_key_for(session: AsyncSession, device_id: int) -> str | None:
    """The key we have agreed to accept for a device, in authorized_keys form."""
    record = await session.scalar(select(SshHostKey).where(SshHostKey.device_id == device_id))
    if record is None:
        return None
    return f"{record.key_type} {record.key_base64}"


async def host_keys_for(session: AsyncSession, device_id: int) -> list[SshHostKey]:
    return list(await session.scalars(select(SshHostKey).where(SshHostKey.device_id == device_id)))


async def probe(device: Device, port: int = 22) -> ssh_client.PresentedKey:
    """Read a device's host key so an operator can review it before trusting."""
    return await ssh_client.probe_host_key(device.ip_address, port)


async def trust(
    session: AsyncSession,
    device: Device,
    key: ssh_client.PresentedKey,
    *,
    user_id: int | None,
    username: str | None,
) -> SshHostKey:
    """Record an operator's decision to accept a host key.

    Deliberately a separate, explicit step rather than something that happens
    automatically on first connection. Trust on first *use* means a human looked
    at a fingerprint and said yes; trust on first *sight* means the application
    accepted whatever answered the address, which is not verification at all.
    """
    existing = await session.scalar(
        select(SshHostKey).where(
            SshHostKey.device_id == device.id, SshHostKey.key_type == key.key_type
        )
    )

    if existing is not None:
        if existing.key_base64 == key.key_base64:
            return existing
        # Replacing a key is a real decision and is logged as one.
        logger.warning(
            "host key for device %s replaced by %r (%s -> %s)",
            device.id,
            username,
            existing.fingerprint,
            key.fingerprint,
        )
        existing.key_base64 = key.key_base64
        existing.fingerprint = key.fingerprint
        existing.trusted_at = datetime.now(UTC)
        existing.trusted_by_user_id = user_id
        existing.trusted_by_snapshot = username
        await session.commit()
        return existing

    record = SshHostKey(
        device_id=device.id,
        key_type=key.key_type,
        key_base64=key.key_base64,
        fingerprint=key.fingerprint,
        trusted_by_user_id=user_id,
        trusted_by_snapshot=username,
    )
    session.add(record)
    await session.commit()

    logger.info("host key %s for device %s trusted by %r", key.fingerprint, device.id, username)
    return record


async def revoke_host_key(session: AsyncSession, device_id: int) -> int:
    """Forget every trusted key for a device.

    Needed when a device is legitimately rebuilt: the next connection then goes
    back through the review step rather than being silently accepted.
    """
    records = await host_keys_for(session, device_id)
    for record in records:
        await session.delete(record)
    if records:
        await session.commit()
        logger.warning("host key trust revoked for device %s", device_id)
    return len(records)
