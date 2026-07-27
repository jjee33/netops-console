"""Login, logout, and password change."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import RedirectResponse, Response

from app.core.requests import client_ip
from app.core.session import current_user_id, end_session, start_session
from app.core.templating import render
from app.modules.auth.dependencies import CurrentUser, SessionDep
from app.modules.auth.service import (
    GENERIC_FAILURE,
    authenticate,
    set_password,
    validate_new_password,
)
from app.modules.auth.throttle import login_throttle

logger = logging.getLogger("netops.auth")

router = APIRouter(tags=["auth"])


def _safe_next(value: str | None) -> str:
    """Only ever return a same-origin path.

    ``//evil.example`` is a protocol-relative URL that browsers treat as
    absolute, so checking for a leading slash alone is not enough.
    """
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    return value


@router.get("/login")
async def login_form(request: Request, next: str = "/") -> Response:
    if current_user_id(request) is not None:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return render(request, "login.html", {"next": _safe_next(next), "error": None})


@router.post("/login")
async def login(
    request: Request,
    session: SessionDep,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
) -> Response:
    ip = client_ip(request)
    target = _safe_next(next)

    if login_throttle.is_limited(ip):
        retry_after = login_throttle.retry_after(ip)
        logger.warning("login rate limit hit from %s", ip)
        return render(
            request,
            "login.html",
            {
                "next": target,
                "error": f"Too many attempts. Try again in {retry_after} seconds.",
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
        )

    result = await authenticate(session, username.strip(), password)

    if not result.ok or result.user is None:
        login_throttle.record_failure(ip)
        logger.warning("failed login for %r from %s", username, ip)
        return render(
            request,
            "login.html",
            # result.error is either the generic message or the lockout notice.
            # Neither reveals whether the account exists.
            {"next": target, "error": result.error or GENERIC_FAILURE},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    login_throttle.reset(ip)
    # Replaces any pre-existing session, which is what defeats fixation.
    start_session(request, result.user.id)
    logger.info("login: %r from %s", result.user.username, ip)

    if result.user.must_change_password:
        return RedirectResponse("/account/password", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/logout")
async def logout(request: Request) -> Response:
    end_session(request)
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/account/password")
async def password_form(request: Request, user: CurrentUser) -> Response:
    return render(
        request,
        "account_password.html",
        {"error": None, "forced": user.must_change_password},
    )


@router.post("/account/password")
async def change_password(
    request: Request,
    session: SessionDep,
    user: CurrentUser,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
) -> Response:
    def fail(message: str) -> Response:
        return render(
            request,
            "account_password.html",
            {"error": message, "forced": user.must_change_password},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Require the current password even though the session is already
    # authenticated: it is what stops a walk-up at an unlocked screen from
    # taking over the account.
    check = await authenticate(session, user.username, current_password)
    if not check.ok:
        logger.warning("password change with wrong current password for %r", user.username)
        return fail("Current password is incorrect.")

    error = validate_new_password(new_password, confirm_password, username=user.username)
    if error:
        return fail(error)

    if new_password == current_password:
        return fail("New password must be different from the current one.")

    await set_password(session, user, new_password)
    # Fresh session id: a password change should invalidate anything that came
    # before it.
    start_session(request, user.id)
    logger.info("password changed for %r", user.username)

    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
