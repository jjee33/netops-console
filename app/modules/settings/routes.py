"""Settings page."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import Response

from app.core.templating import render
from app.core.validation import ValidationError
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.history.changes import describe_changes, record_change
from app.modules.settings import service

logger = logging.getLogger("netops.settings")

router = APIRouter(tags=["settings"])


def _context(settings: service.AppSettings, **extra: object) -> dict[str, object]:
    return {
        "settings": settings,
        "allowed_cidrs_text": "\n".join(settings.allowed_cidrs),
        "error": None,
        "saved": False,
        **extra,
    }


def _comparable(settings: service.AppSettings) -> dict[str, object]:
    return {
        "allowed ranges": ", ".join(settings.allowed_cidrs) or None,
        "scan host cap": settings.max_scan_hosts,
        "concurrent scans": settings.max_concurrent_scans,
        "concurrent executions": settings.max_concurrent_executions,
        "retention days": settings.retention_days,
        "strict host keys": settings.strict_host_keys,
    }


@router.get("/settings")
async def settings_page(request: Request, session: SessionDep, user: ActiveUser) -> Response:
    settings = await service.load(session)
    return render(request, "settings.html", _context(settings))


@router.post("/settings")
async def update_settings(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    allowed_cidrs: Annotated[str, Form()],
    max_scan_hosts: Annotated[str, Form()],
    max_concurrent_scans: Annotated[str, Form()],
    max_concurrent_executions: Annotated[str, Form()],
    retention_days: Annotated[str, Form()],
    strict_host_keys: Annotated[str | None, Form()] = None,
) -> Response:
    previous = await service.load(session)
    try:
        settings = await service.save(
            session,
            allowed_cidrs_raw=allowed_cidrs,
            max_scan_hosts=max_scan_hosts,
            max_concurrent_scans=max_concurrent_scans,
            max_concurrent_executions=max_concurrent_executions,
            retention_days=retention_days,
            strict_host_keys=strict_host_keys is not None,
            commit=False,
        )
    except ValidationError as exc:
        # Re-render with what the operator typed rather than what was stored,
        # so a rejected save does not silently discard their edits.
        current = await service.load(session)
        return render(
            request,
            "settings.html",
            _context(current, error=str(exc), allowed_cidrs_text=allowed_cidrs),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    detail = describe_changes(_comparable(previous), _comparable(settings))
    if detail:
        record_change(session, request, user, "settings_changed", detail=detail)
    await session.commit()

    logger.info("settings updated by %r: cidrs=%s", user.username, settings.allowed_cidrs)
    return render(request, "settings.html", _context(settings, saved=True))
