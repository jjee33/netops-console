"""SSH connections with strict host key verification.

The single most important thing in this module is what it refuses to do. It will
not connect to a device whose host key is unknown, and it will not connect to
one whose key has changed. Both cases stop and ask a human.

That is not caution about a rare attack; it is the only thing that makes an SSH
credential store meaningful. A client that accepts any host key hands the
credential to whoever answers the address, which turns the credential store from
a security feature into an efficient way to leak keys.

The three outcomes a caller must handle:

``UnknownHostKey``
    Nothing is trusted for this device yet. The fingerprint is presented and no
    credential is offered. An operator accepts it, or does not.

``HostKeyChanged``
    A key exists and the device presented a different one. Always an error —
    either the device was rebuilt or something is impersonating it, and only the
    operator knows which.

success
    The presented key matched the stored one exactly.

Implementation note: verification is done by handing asyncssh a ``known_hosts``
callable that returns exactly the one key we trust for this device. There is no
path through this module that sets ``known_hosts=None`` for a connection that
carries a credential — the only place it is disabled is the unauthenticated
probe below, which offers nothing.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

import asyncssh

from app.core.crypto import decrypt

logger = logging.getLogger("netops.ssh")

CONNECT_TIMEOUT = 15
LOGIN_TIMEOUT = 20


@dataclass(frozen=True)
class PresentedKey:
    """A host key a device offered, before any trust decision."""

    key_type: str
    key_base64: str
    fingerprint: str

    @property
    def openssh(self) -> str:
        """The key in ``authorized_keys`` form, for storage and comparison."""
        return f"{self.key_type} {self.key_base64}"


class SshError(Exception):
    """Base for problems reaching or authenticating to a device."""


class UnknownHostKey(SshError):
    """The device is not yet trusted. Carries the key for the operator to review."""

    def __init__(self, key: PresentedKey) -> None:
        super().__init__(
            f"This device's identity has not been verified. It presented a "
            f"{key.key_type} key with fingerprint {key.fingerprint}. Compare that "
            f"against the device itself before trusting it."
        )
        self.key = key


class HostKeyChanged(SshError):
    """The device presented a different key than the one on record."""

    def __init__(self, expected: str, presented: PresentedKey | None) -> None:
        shown = presented.fingerprint if presented else "(could not be read)"
        super().__init__(
            f"This device presented a different host key than the one previously "
            f"trusted.\n\n  expected:  {expected}\n  presented: {shown}\n\n"
            f"If the device was rebuilt or its keys were regenerated, remove the "
            f"stored key and trust the new one. If it was not, something is "
            f"impersonating this device and the connection was correctly refused."
        )
        self.expected = expected
        self.presented = presented


def describe_key(key: asyncssh.SSHKey) -> PresentedKey:
    """Summarise a key for storage and display.

    Public material only — a host key is public by definition, but the shape of
    this function is deliberate: nothing anywhere returns private key material.
    """
    export = key.export_public_key().decode("utf-8", errors="replace").strip()
    parts = export.split()

    return PresentedKey(
        key_type=parts[0] if parts else "unknown",
        key_base64=parts[1] if len(parts) > 1 else "",
        fingerprint=key.get_fingerprint(),
    )


async def probe_host_key(host: str, port: int = 22) -> PresentedKey:
    """Read a device's host key without authenticating.

    Used by the trust workflow so an operator can review a fingerprint before
    any credential exists for the device. This performs the key exchange only —
    it never reaches authentication, so nothing is offered to the far end.
    """
    try:
        # get_server_host_key takes no connect_timeout of its own, so the bound
        # is applied here — an unreachable address must not hang the request.
        async with asyncio.timeout(CONNECT_TIMEOUT):
            key = await asyncssh.get_server_host_key(host, port=port)
    except TimeoutError as exc:
        raise SshError(f"{host}:{port} did not respond within {CONNECT_TIMEOUT}s.") from exc
    except (OSError, asyncssh.Error) as exc:
        raise SshError(f"Could not reach {host}:{port} to read its host key: {exc}") from exc

    if key is None:
        raise SshError(f"{host}:{port} did not present a host key.")
    return describe_key(key)


@dataclass(frozen=True)
class SshResult:
    exit_status: int | None
    stdout: str
    stderr: str


def _known_hosts_for(trusted: str):
    """Build a known_hosts callable that trusts exactly one key.

    asyncssh calls this during key exchange and expects
    ``(trusted_host_keys, trusted_ca_keys, revoked_host_keys)``. Returning a
    single key means anything else raises HostKeyNotVerifiable before
    authentication begins — which is the property that matters, since it means
    the credential is never presented to a host we cannot identify.
    """
    key = asyncssh.import_public_key(trusted)

    def resolve(_host: str, _addr: str, _port: int) -> tuple[list, list, list]:
        return ([key], [], [])

    return resolve


async def run_command(
    host: str,
    command: str,
    *,
    username: str,
    auth_type: str,
    secret_ciphertext: bytes,
    passphrase_ciphertext: bytes | None,
    trusted_key: str | None,
    port: int = 22,
    # asyncssh applies this to the remote command itself, which a caller-side
    # asyncio.timeout cannot do — cancelling here would abandon a running
    # command on the device rather than bounding it.
    timeout: float = 30.0,  # noqa: ASYNC109
) -> SshResult:
    """Run one command on a device, verifying its host key first.

    ``trusted_key`` is the stored key in ``authorized_keys`` form
    (``"ssh-ed25519 AAAA..."``). Passing ``None`` raises
    :class:`UnknownHostKey` after probing — no credential is ever offered to an
    unverified host.
    """
    if trusted_key is None:
        # Probe rather than connect: the operator needs the fingerprint, and
        # this path must not authenticate.
        raise UnknownHostKey(await probe_host_key(host, port))

    options: dict[str, Any] = {
        "username": username,
        "known_hosts": _known_hosts_for(trusted_key),
        "connect_timeout": CONNECT_TIMEOUT,
        "login_timeout": LOGIN_TIMEOUT,
    }

    # Decrypted as late as possible and not held beyond this call.
    secret = decrypt(secret_ciphertext)
    passphrase = decrypt(passphrase_ciphertext) if passphrase_ciphertext else None

    if auth_type == "ssh_key":
        try:
            options["client_keys"] = [asyncssh.import_private_key(secret, passphrase)]
        except asyncssh.KeyImportError as exc:
            raise SshError(
                "The stored private key could not be read. If it is passphrase "
                "protected, the passphrase is missing or wrong."
            ) from exc
    else:
        options["password"] = secret
        options["client_keys"] = []

    try:
        async with asyncssh.connect(host, port=port, **options) as connection:
            result = await connection.run(command, timeout=timeout, check=False)

    except asyncssh.HostKeyNotVerifiable as exc:
        # The device answered with something other than the key we trust. Read
        # what it actually offered so the operator can compare fingerprints.
        try:
            presented = await probe_host_key(host, port)
        except SshError:
            presented = None
        raise HostKeyChanged(_fingerprint_of(trusted_key), presented) from exc

    except asyncssh.PermissionDenied as exc:
        raise SshError(
            f"Authentication failed for {username}@{host}. Check the username and "
            f"that this credential is authorised on the device."
        ) from exc

    except TimeoutError as exc:
        raise SshError(f"{host} did not respond within {timeout:.0f}s.") from exc

    except (OSError, asyncssh.Error) as exc:
        raise SshError(f"Could not connect to {host}:{port}: {exc}") from exc

    finally:
        # Not a security control by itself — Python strings are immutable and
        # this only drops a reference — but it keeps the plaintext out of any
        # traceback captured after this point.
        del secret, passphrase

    return SshResult(
        exit_status=result.exit_status,
        stdout=_as_text(result.stdout),
        stderr=_as_text(result.stderr),
    )


def _as_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _fingerprint_of(trusted_key: str) -> str:
    try:
        return asyncssh.import_public_key(trusted_key).get_fingerprint()
    except (asyncssh.KeyImportError, ValueError):  # pragma: no cover - stored keys are valid
        return "(stored key unreadable)"
