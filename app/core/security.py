"""Password hashing and secret generation.

Argon2id with the argon2-cffi defaults, which track the RFC 9106 second
recommended profile. Verification deliberately runs even for a username that
does not exist, so response timing does not disclose which accounts are real.
"""

from __future__ import annotations

import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher()

# A hash of a random throwaway value, used to burn the same CPU time on a
# missing user as on a real one.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))

# Unambiguous alphabet: no O/0, l/1/I. Generated passwords get read off a
# terminal and typed by hand at least once.
_PASSWORD_ALPHABET = (
    "".join(c for c in string.ascii_letters if c not in "lIO")
    + "".join(c for c in string.digits if c not in "01")
    + "-_"
)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Verify a password, taking constant-ish time whether or not the user exists.

    Pass ``None`` for an unknown user rather than short-circuiting at the call
    site — the dummy verify is what removes the timing oracle.
    """
    try:
        _hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    return password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def generate_password(length: int = 24) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))
