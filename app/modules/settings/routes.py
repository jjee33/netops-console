"""Settings page."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import Response

from app.core.templating import render
from app.core.validation import ValidationError
from app.modules.auth.dependencies import ActiveUser, SessionDep
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
    try:
        settings = await service.save(
            session,
            allowed_cidrs_raw=allowed_cidrs,
            max_scan_hosts=max_scan_hosts,
            max_concurrent_scans=max_concurrent_scans,
            max_concurrent_executions=max_concurrent_executions,
            retention_days=retention_days,
            strict_host_keys=strict_host_keys is not None,
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

    logger.info("settings updated by %r: cidrs=%s", user.username, settings.allowed_cidrs)
    return render(request, "settings.html", _context(settings, saved=True))
