"""Authentication logic.

The design constraint that shapes everything here: an attacker must not be able
to learn whether a username exists. That means the same message, the same work,
and the same code path for "no such user" and "wrong password".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, needs_rehash, verify_password
from app.models import User

logger = logging.getLogger("netops.auth")

# Lockout kicks in after this many consecutive failures, then backs off
# exponentially: 1, 2, 4, 8... minutes, capped.
LOCKOUT_THRESHOLD: Final = 5
LOCKOUT_BASE: Final = timedelta(minutes=1)
LOCKOUT_MAX: Final = timedelta(minutes=30)

# One message for every failure mode. Never "unknown user" or "wrong password".
GENERIC_FAILURE: Final = "Invalid username or password."
LOCKED_MESSAGE: Final = "Too many failed attempts. Try again later."


@dataclass(frozen=True)
class AuthResult:
    user: User | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.user is not None


def _now() -> datetime:
    return datetime.now(UTC)


def _lockout_duration(failure_count: int) -> timedelta:
    """Exponential backoff past the threshold, clamped."""
    excess = max(0, failure_count - LOCKOUT_THRESHOLD)
    duration = LOCKOUT_BASE * (2**excess)
    return min(duration, LOCKOUT_MAX)


def is_locked(user: User, *, now: datetime | None = None) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        # SQLite hands back naive datetimes even for timezone-aware columns.
        locked_until = locked_until.replace(tzinfo=UTC)
    return locked_until > (now or _now())


async def authenticate(session: AsyncSession, username: str, password: str) -> AuthResult:
    """Verify credentials, applying and updating the per-account lockout."""
    user = await session.scalar(select(User).where(User.username == username))

    # Runs even when the user does not exist. verify_password hashes a dummy
    # value in that case, so the response takes the same time either way and
    # the endpoint cannot be used to enumerate accounts.
    password_ok = verify_password(password, user.password_hash if user else None)

    if user is None:
        return AuthResult(None, GENERIC_FAILURE)

    if is_locked(user):
        # Checked after the hash so a locked account and a live one are not
        # distinguishable by response time either.
        logger.warning("login attempt on locked account %r", username)
        return AuthResult(None, LOCKED_MESSAGE)

    if not user.is_active:
        logger.warning("login attempt on disabled account %r", username)
        return AuthResult(None, GENERIC_FAILURE)

    if not password_ok:
        user.failed_login_count += 1
        if user.failed_login_count >= LOCKOUT_THRESHOLD:
            user.locked_until = _now() + _lockout_duration(user.failed_login_count)
            logger.warning(
                "account %r locked until %s after %d failures",
                username,
                user.locked_until,
                user.failed_login_count,
            )
        await session.commit()
        return AuthResult(None, GENERIC_FAILURE)

    # Success: clear the counters and opportunistically upgrade the hash if the
    # argon2 parameters have moved on since it was written.
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = _now()
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    await session.commit()

    return AuthResult(user)


async def set_password(session: AsyncSession, user: User, new_password: str) -> None:
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.failed_login_count = 0
    user.locked_until = None
    await session.commit()


MIN_PASSWORD_LENGTH: Final = 12


def validate_new_password(password: str, confirmation: str, *, username: str) -> str | None:
    """Return an error message, or None if the password is acceptable.

    Length only, plus the obvious footgun of reusing the username. Composition
    rules ("one uppercase, one symbol") push people toward predictable
    substitutions and are not applied here; NIST stopped recommending them.
    """
    if password != confirmation:
        return "The two passwords do not match."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if password.strip().lower() == username.strip().lower():
        return "Password must not be the same as the username."
    return None
