"""Authentication dependencies.

``require_user`` is the gate on every page except login and the health probe.
It redirects browsers rather than returning 401, because a 401 on an HTML
request shows a blank page or a browser auth prompt, neither of which is what
an operator whose session expired should see.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_session
from app.core.session import current_user_id, touch
from app.models import User

SessionDep = Annotated[AsyncSession, Depends(get_session)]


class RedirectToLogin(HTTPException):
    """Raised when an unauthenticated request reaches a protected page.

    An exception rather than a returned response so it works from anywhere in
    the dependency tree; the handler in main.py turns it into a redirect.
    """

    def __init__(self, next_url: str) -> None:
        super().__init__(status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        self.next_url = next_url


async def get_current_user(request: Request, session: SessionDep) -> User:
    user_id = current_user_id(request)
    if user_id is None:
        raise RedirectToLogin(request.url.path)

    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        # The account was deleted or disabled while the session was live.
        request.session.clear()
        raise RedirectToLogin(request.url.path)

    touch(request)
    request.state.user = user
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def require_password_change_complete(request: Request, user: CurrentUser) -> User:
    """Block the rest of the application until a generated password is rotated.

    The bootstrap password is printed to container logs, so it should be
    treated as known by anyone who can read them. Allowing normal use before it
    is changed would make that exposure permanent.
    """
    if user.must_change_password and request.url.path != "/account/password":
        raise MustChangePassword()
    return user


class MustChangePassword(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=status.HTTP_307_TEMPORARY_REDIRECT)


ActiveUser = Annotated[User, Depends(require_password_change_complete)]


def redirect_to_login(next_url: str | None = None) -> RedirectResponse:
    target = "/login"
    if next_url and next_url != "/" and next_url.startswith("/") and "//" not in next_url:
        # Only ever a same-origin path — never echo a caller-supplied absolute
        # URL into a redirect, which is an open-redirect handed to a phisher.
        target = f"/login?next={next_url}"
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
