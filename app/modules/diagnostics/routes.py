"""Diagnostic endpoints.

Device-scoped and type-scoped: the URL names which of a fixed set of
diagnostics to run, and the only free values are a bounded port and count.
There is no endpoint anywhere that accepts a command.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import Response

from app.core.requests import client_ip
from app.core.templating import render
from app.core.validation import ValidationError
from app.models import Device, DiagnosticResult
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.diagnostics import service
from app.modules.settings import service as settings_service

logger = logging.getLogger("netops.diagnostics")

router = APIRouter(tags=["diagnostics"])


@router.post("/devices/{device_id}/diagnostics/{kind}")
async def run_diagnostic(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    device_id: int,
    kind: str,
    port: Annotated[int | None, Form()] = None,
    count: Annotated[int | None, Form()] = None,
) -> Response:
    device = await session.get(Device, device_id)
    if device is None or device.is_deleted:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    if kind not in service.REGISTRY:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    settings = await settings_service.load(session)

    try:
        result = await service.run_diagnostic(
            session,
            device,
            kind,
            settings.allowed_networks,
            user_id=user.id,
            username=user.username,
            client_ip=client_ip(request),
            port=port,
            count=count,
        )
    except ValidationError as exc:  # pragma: no cover - registry checked above
        logger.warning("diagnostic rejected: %s", exc)
        return render(request, "not_found.html", {}, status_code=status.HTTP_400_BAD_REQUEST)

    # Retention runs opportunistically after execution: this is the code path
    # that creates the volume, so it is the right one to pay the cleanup cost.
    await service.prune(session, settings.retention_days)

    return render(
        request,
        "partials/diagnostic_result.html",
        {
            "result": result,
            "spec": service.REGISTRY[kind],
            "summary": service.result_summary(result),
            "device": device,
        },
    )


@router.get("/diagnostics/{result_id}")
async def diagnostic_detail(
    request: Request, session: SessionDep, user: ActiveUser, result_id: int
) -> Response:
    result = await session.get(DiagnosticResult, result_id)
    if result is None:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    device = await session.get(Device, result.device_id) if result.device_id else None

    return render(
        request,
        "partials/diagnostic_result.html",
        {
            "result": result,
            "spec": service.REGISTRY.get(result.type),
            "summary": service.result_summary(result),
            "device": device,
        },
    )
