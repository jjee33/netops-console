"""Device history, scan reports and scan comparison.

Read-only, every route. Nothing here runs a command or changes a record, so
there are no POST routes and nothing for CSRF to protect — but every value
rendered came from the network or from an operator, so all of it is escaped.
"""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Request, status
from fastapi.responses import Response
from sqlalchemy import select

from app.core.templating import render
from app.models import Device, DiscoveryRun
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.discovery.explain import explain_run
from app.modules.history import service

router = APIRouter(tags=["history"])


@router.get("/devices/{device_id}/history")
async def device_history(
    request: Request, session: SessionDep, user: ActiveUser, device_id: int
) -> Response:
    device = await session.get(Device, device_id)
    if device is None or device.is_deleted:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    timeline = await service.device_timeline(session, device)
    return render(request, "device_history.html", {"device": device, "timeline": timeline})


def _address_key(address: str) -> tuple[int, ...]:
    try:
        return tuple(ipaddress.ip_address(address).packed)
    except ValueError:  # pragma: no cover - validated at scan time
        return (255,)


@router.get("/discovery/runs/{run_id}/report")
async def run_report(
    request: Request, session: SessionDep, user: ActiveUser, run_id: int
) -> Response:
    run = await session.get(DiscoveryRun, run_id)
    if run is None:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    observations = sorted(
        await service.run_observations(session, run.id),
        # Answering hosts first, then by address, which is how people read a subnet.
        key=lambda row: (not row.present, _address_key(row.ip_address)),
    )
    referenced = {row.device_id for row in observations if row.device_id}
    # Only link devices that still exist in the inventory; a removed device's
    # page is a 404, and the observation row already shows what was seen.
    live_devices = (
        set(
            await session.scalars(
                select(Device.id).where(Device.id.in_(referenced), Device.is_deleted.is_(False))
            )
        )
        if referenced
        else set()
    )

    return render(
        request,
        "run_report.html",
        {
            "run": run,
            "observations": observations,
            "live_devices": live_devices,
            "describe_ports": service.describe_ports,
            "has_results": service.has_host_results(run, len(observations)),
            "no_results_reason": service.why_no_host_results(run),
            "previous": await service.previous_comparable_run(session, run),
            "explanation": explain_run(run, observations),
        },
    )


@router.get("/discovery/compare")
async def compare_runs(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    base: int | None = None,
    target: int | None = None,
) -> Response:
    candidates = await service.runs_with_results(session)

    # With nothing chosen, default to the two most recent comparable scans of
    # the same range — the comparison someone opening this page usually wants.
    if base is None and target is None and candidates:
        latest = candidates[0]
        earlier = await service.previous_comparable_run(session, latest)
        if earlier is not None:
            base, target = earlier.id, latest.id

    comparison = None
    error = None
    if base is not None and target is not None:
        base_run = await session.get(DiscoveryRun, base)
        target_run = await session.get(DiscoveryRun, target)
        if base_run is None or target_run is None:
            return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)
        if base_run.id == target_run.id:
            error = "Choose two different scans to compare."
        else:
            # Always read as "what changed since": earlier on the left.
            if base_run.id > target_run.id:
                base_run, target_run = target_run, base_run
            comparison = await service.compare_runs(session, base_run, target_run)

    return render(
        request,
        "run_compare.html",
        {
            "candidates": candidates,
            "base": base,
            "target": target,
            "comparison": comparison,
            "error": error,
        },
    )
