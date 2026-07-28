"""Encryption for stored credentials.

Fernet (AES-128-CBC with an HMAC-SHA256 authentication tag) keyed by the
``crypto_key`` generated at first start. Authenticated encryption is the
requirement, not a preference: without it, ciphertext in the database could be
altered and the change would surface as a mangled key rather than as an error.

The threat this addresses and the one it does not:

* **Addressed** — someone obtains a copy of the database, from a backup, a
  stolen volume, or a misconfigured share. Without the key it yields nothing.
* **Not addressed** — someone who can read the running container's filesystem
  or memory. They have the key. That is why the threat model treats Docker
  access as root-equivalent and why the key is stored outside the database
  rather than pretending to defend against a local attacker.

Consequently the key must be backed up *separately* from the database. Keeping
both in one archive means one stolen backup yields both the ciphertext and the
key, which is the same as not encrypting at all.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

logger = logging.getLogger("netops.crypto")


class DecryptionError(Exception):
    """Ciphertext could not be decrypted with the current key."""


@lru_cache(maxsize=1)
def _cipher() -> Fernet:
    """Build the cipher once. Cached because the key is read from disk."""
    key = get_settings().read_crypto_key()
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            "The credential-encryption key is not a valid Fernet key. It must be "
            "32 random bytes, urlsafe-base64 encoded. If it has been replaced or "
            "corrupted, restore the original — a different key cannot decrypt "
            "credentials stored under the old one."
        ) from exc


def reset_cipher() -> None:
    """Drop the cached cipher. For tests and key rotation."""
    _cipher.cache_clear()


def encrypt(plaintext: str) -> bytes:
    """Encrypt a secret for storage. Never returns the plaintext on any path."""
    if not plaintext:
        raise ValueError("Refusing to encrypt an empty secret.")
    return _cipher().encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes) -> str:
    """Decrypt a stored secret.

    Raises :class:`DecryptionError` rather than returning anything on failure,
    so a wrong key can never be mistaken for an empty password. The exception
    message deliberately contains no fragment of the ciphertext.
    """
    try:
        return _cipher().decrypt(ciphertext).decode("utf-8")
    except InvalidToken as exc:
        logger.error("credential decryption failed — wrong key, or altered ciphertext")
        raise DecryptionError(
            "This credential could not be decrypted. Either the encryption key has "
            "changed since it was stored, or the stored value has been altered. "
            "Restore the original key from backup, or re-enter the credential."
        ) from exc


def fingerprint(public_material: str) -> str:
    """A short, non-secret identifier for displaying a key in the UI.

    Computed over public material only — the point is to let an operator tell
    two keys apart without the application ever showing key material.
    """
    import base64
    import hashlib

    digest = hashlib.sha256(public_material.encode("utf-8")).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
