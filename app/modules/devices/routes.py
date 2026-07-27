"""Dashboard.

A shell in Phase 1 — the device model and discovery land in Phase 2. It exists
now so the login flow has somewhere to arrive and the navigation is real.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from app.core.templating import render
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.settings import service as settings_service

router = APIRouter(tags=["dashboard"])


@router.get("/")
async def dashboard(request: Request, session: SessionDep, user: ActiveUser) -> Response:
    settings = await settings_service.load(session)

    return render(
        request,
        "dashboard.html",
        {
            "stats": {"total": 0, "online": 0, "offline": 0, "unknown": 0},
            "devices": [],
            "allowed_cidrs": settings.allowed_cidrs,
        },
    )
