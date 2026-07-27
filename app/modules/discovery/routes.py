"""Discovery pages.

Scans run as background tasks and the page polls for the result. Running them
inline would be simpler, but a scan of a /24 can take a minute or more and most
reverse proxies give up well before that — the operator would see a gateway
timeout while the scan was in fact working.

There is no output *streaming* in v0.1. The poll reports status only, so the UI
shows a spinner and an elapsed time rather than implying live progress.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import Response
from sqlalchemy import select

from app.core.db import get_session_factory
from app.core.requests import client_ip, wants_partial
from app.core.templating import render
from app.core.validation import ValidationError, validate_scan_target
from app.models import DiscoveryRun
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.discovery import service
from app.modules.settings import service as settings_service

logger = logging.getLogger("netops.discovery")

router = APIRouter(tags=["discovery"])

RECENT_RUN_LIMIT = 25

# asyncio keeps only a weak reference to a running task, so a task nobody holds
# can be garbage collected mid-execution. Holding them here is what stops a scan
# vanishing silently part-way through.
_background_tasks: set[asyncio.Task[None]] = set()


async def _recent_runs(session: SessionDep) -> list[DiscoveryRun]:
    return list(
        await session.scalars(
            select(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(RECENT_RUN_LIMIT)
        )
    )


async def _scan(
    run_id: int,
    subnet: str,
    allowed: list[ipaddress.IPv4Network],
    max_hosts: int,
    with_ports: bool,
) -> None:
    """Execute a scan against its own session, outside the request lifecycle."""
    async with get_session_factory()() as session:
        run = await session.get(DiscoveryRun, run_id)
        if run is None:  # pragma: no cover - defensive
            return
        try:
            await service.execute_run(
                session, run, subnet, allowed, max_hosts, with_ports=with_ports
            )
        except Exception:
            # A background task that dies quietly leaves a run stuck on
            # "running" forever, which reads as a hung application.
            logger.exception("discovery run %s failed unexpectedly", run_id)
            await service.mark_failed(session, run, "Scan failed unexpectedly. Check the logs.")


@router.get("/discovery")
async def discovery_page(request: Request, session: SessionDep, user: ActiveUser) -> Response:
    settings = await settings_service.load(session)
    return render(
        request,
        "discovery.html",
        {
            "settings": settings,
            "runs": await _recent_runs(session),
            "error": None,
            "active_run": None,
        },
    )


@router.post("/discovery/run")
async def start_discovery(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    subnet: Annotated[str, Form()],
    scan_ports: Annotated[str | None, Form()] = None,
) -> Response:
    settings = await settings_service.load(session)
    target = subnet.strip()

    # Validate before creating a run row, so a typo does not litter the history
    # with rejected entries.
    try:
        network = validate_scan_target(target, settings.allowed_networks, settings.max_scan_hosts)
    except ValidationError as exc:
        return render(
            request,
            "discovery.html",
            {
                "settings": settings,
                "runs": await _recent_runs(session),
                "error": str(exc),
                "active_run": None,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    run = await service.create_run(
        session,
        str(network),
        user_id=user.id,
        username=user.username,
        client_ip=client_ip(request),
    )

    task = asyncio.create_task(
        _scan(
            run.id,
            str(network),
            settings.allowed_networks,
            settings.max_scan_hosts,
            scan_ports is not None,
        )
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    logger.info("discovery run %s started for %s by %r", run.id, network, user.username)

    return render(
        request,
        "discovery.html",
        {
            "settings": settings,
            "runs": await _recent_runs(session),
            "error": None,
            "active_run": run,
        },
    )


@router.get("/discovery/runs/{run_id}")
async def run_status(
    request: Request, session: SessionDep, user: ActiveUser, run_id: int
) -> Response:
    run = await session.get(DiscoveryRun, run_id)
    if run is None:
        return Response(status_code=status.HTTP_404_NOT_FOUND)

    response = render(request, "partials/run_status.html", {"run": run})
    if run.status != "running" and wants_partial(request):
        # Tells HTMX to stop polling. Without it the browser keeps requesting
        # this endpoint for as long as the page is open.
        response.headers["HX-Reswap"] = "outerHTML"
    return response
