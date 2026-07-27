"""Session state and CSRF protection.

Sessions are signed cookies (Starlette's ``SessionMiddleware``). That is a
deliberate v0.1 simplification: there is one operator and one process, so a
server-side session store buys little. The consequence is that a session cannot
be revoked server-side before it expires, which is why both expiries below are
short and why ``sid`` exists.

``sid`` is a random value regenerated on every login. It gives us the one thing
cookie sessions otherwise lack: a fixation-resistant identity. An attacker who
plants a session cookie before login finds it replaced the moment the user
authenticates.
"""

from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Final

from starlette.requests import Request

SESSION_USER_ID: Final = "user_id"
SESSION_SID: Final = "sid"
SESSION_CSRF: Final = "csrf"
SESSION_CREATED_AT: Final = "created_at"
SESSION_LAST_SEEN: Final = "last_seen"

# Absolute lifetime: a session dies this long after login no matter how active.
# Idle lifetime: a session dies this long after the last request.
ABSOLUTE_LIFETIME: Final = timedelta(hours=12)
IDLE_LIFETIME: Final = timedelta(minutes=60)

CSRF_HEADER: Final = "X-CSRF-Token"
CSRF_FIELD: Final = "csrf_token"


def _now() -> datetime:
    return datetime.now(UTC)


def start_session(request: Request, user_id: int) -> None:
    """Establish an authenticated session, discarding anything already there.

    The clear() is the anti-fixation step: any session the client arrived with
    is destroyed rather than adopted.
    """
    request.session.clear()
    now = _now()
    request.session.update(
        {
            SESSION_USER_ID: user_id,
            SESSION_SID: secrets.token_urlsafe(32),
            SESSION_CSRF: secrets.token_urlsafe(32),
            SESSION_CREATED_AT: now.isoformat(),
            SESSION_LAST_SEEN: now.isoformat(),
        }
    )


def end_session(request: Request) -> None:
    request.session.clear()


def current_user_id(request: Request) -> int | None:
    """Return the authenticated user id, or None if the session is absent or expired.

    Expiry is enforced here rather than left to the cookie's own max-age,
    because a cookie lifetime is a client-side hint and this is not.
    """
    user_id = request.session.get(SESSION_USER_ID)
    if user_id is None:
        return None

    created = _parse(request.session.get(SESSION_CREATED_AT))
    last_seen = _parse(request.session.get(SESSION_LAST_SEEN))
    if created is None or last_seen is None:
        return None

    now = _now()
    if now - created > ABSOLUTE_LIFETIME or now - last_seen > IDLE_LIFETIME:
        request.session.clear()
        return None

    return int(user_id)


def touch(request: Request) -> None:
    """Slide the idle window forward. Call once per authenticated request."""
    request.session[SESSION_LAST_SEEN] = _now().isoformat()


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


def get_csrf_token(request: Request) -> str:
    """Return the session's CSRF token, minting one if needed.

    Unauthenticated visitors get a token too — the login form itself is a POST
    and needs one.
    """
    token = request.session.get(SESSION_CSRF)
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        request.session[SESSION_CSRF] = token
    return token


def verify_csrf(request: Request, submitted: str | None) -> bool:
    """Compare a submitted token against the session's, in constant time.

    A synchronizer token, not double-submit: the expected value lives in the
    signed session, so an attacker who can set cookies still cannot forge it.
    """
    expected = request.session.get(SESSION_CSRF)
    if not isinstance(expected, str) or not expected or not submitted:
        return False
    return hmac.compare_digest(expected, submitted)
