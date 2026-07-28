"""Dashboard, device list, and device detail."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select

from app.core.requests import wants_partial
from app.core.templating import render
from app.models import Device, DevicePort, DiscoveryRun
from app.modules.actions import service as actions_service
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.credentials import service as credentials_service
from app.modules.diagnostics import service as diagnostics_service
from app.modules.settings import service as settings_service

logger = logging.getLogger("netops.devices")

router = APIRouter(tags=["devices"])

SORTABLE = {
    "ip": Device.ip_address,
    "name": Device.name,
    "hostname": Device.hostname,
    "vendor": Device.vendor,
    "status": Device.status,
    "last_seen": Device.last_seen,
}


# A device first seen inside this window counts as new. Long enough to survive
# a weekend away, short enough that the number stays meaningful.
NEW_DEVICE_DAYS = 7


def _new_since() -> datetime:
    return datetime.now(UTC) - timedelta(days=NEW_DEVICE_DAYS)


async def _stats(session: SessionDep) -> dict[str, int]:
    rows = await session.execute(
        select(Device.status, func.count())
        .where(Device.is_deleted.is_(False))
        .group_by(Device.status)
    )
    counts: dict[str, int] = {status: count for status, count in rows.all()}

    new_count = await session.scalar(
        select(func.count())
        .select_from(Device)
        .where(Device.is_deleted.is_(False), Device.first_seen >= _new_since())
    )

    return {
        "total": sum(counts.values()),
        "online": counts.get("online", 0),
        "offline": counts.get("offline", 0),
        "unknown": counts.get("unknown", 0) + counts.get("warning", 0),
        "new": new_count or 0,
    }


@router.get("/")
async def dashboard(request: Request, session: SessionDep, user: ActiveUser) -> Response:
    settings = await settings_service.load(session)

    recent = list(
        await session.scalars(
            select(Device)
            .where(Device.is_deleted.is_(False))
            .order_by(Device.last_seen.desc())
            .limit(10)
        )
    )
    runs = list(
        await session.scalars(
            select(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(5)
        )
    )

    # Listed, not just counted. "Three devices appeared this week" is a prompt
    # to look; naming them is what makes it actionable.
    new_devices = list(
        await session.scalars(
            select(Device)
            .where(Device.is_deleted.is_(False), Device.first_seen >= _new_since())
            .order_by(Device.first_seen.desc())
            .limit(10)
        )
    )

    return render(
        request,
        "dashboard.html",
        {
            "stats": await _stats(session),
            "devices": recent,
            "runs": runs,
            "new_devices": new_devices,
            "new_device_days": NEW_DEVICE_DAYS,
            "allowed_cidrs": settings.allowed_cidrs,
        },
    )


@router.get("/devices")
async def device_list(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    q: str = "",
    sort: str = "ip",
    direction: str = "asc",
    new: str = "",
) -> Response:
    column = SORTABLE.get(sort, Device.ip_address)
    ordering = column.desc() if direction == "desc" else column.asc()

    statement = select(Device).where(Device.is_deleted.is_(False))

    show_new = new in ("1", "true", "yes")
    if show_new:
        statement = statement.where(Device.first_seen >= _new_since())

    if q.strip():
        # Bound parameters throughout — the search term is never concatenated
        # into SQL.
        term = f"%{q.strip()}%"
        statement = statement.where(
            Device.ip_address.ilike(term)
            | Device.hostname.ilike(term)
            | Device.name.ilike(term)
            | Device.vendor.ilike(term)
            | Device.mac_address.ilike(term)
        )

    devices = list(await session.scalars(statement.order_by(ordering).limit(500)))

    context = {
        "devices": devices,
        "q": q,
        "sort": sort,
        "direction": direction,
        "next_direction": "desc" if direction == "asc" else "asc",
        "show_new": show_new,
        "new_device_days": NEW_DEVICE_DAYS,
    }

    if wants_partial(request):
        return render(request, "partials/device_table.html", context)
    return render(request, "devices.html", context)


@router.get("/devices/{device_id}")
async def device_detail(
    request: Request, session: SessionDep, user: ActiveUser, device_id: int
) -> Response:
    device = await session.get(Device, device_id)
    if device is None or device.is_deleted:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    ports = list(
        await session.scalars(
            select(DevicePort).where(DevicePort.device_id == device.id).order_by(DevicePort.port)
        )
    )

    return render(
        request,
        "device_detail.html",
        {
            "device": device,
            "ports": ports,
            "registry": diagnostics_service.REGISTRY,
            "history": await diagnostics_service.recent_for_device(session, device.id),
            "actions": await actions_service.actions_for_device(session, device),
            "assigned_credentials": await credentials_service.for_device(session, device.id),
            "all_credentials": await credentials_service.list_all(session),
            "host_keys": await credentials_service.host_keys_for(session, device.id),
        },
    )


@router.post("/devices/{device_id}")
async def update_device(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    device_id: int,
    name: Annotated[str, Form()] = "",
    device_type: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
) -> Response:
    device = await session.get(Device, device_id)
    if device is None or device.is_deleted:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    device.name = name.strip() or None
    device.device_type = device_type.strip() or None
    device.notes = notes.strip() or None
    await session.commit()

    logger.info("device %s updated by %r", device_id, user.username)
    return RedirectResponse(f"/devices/{device_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/devices/{device_id}/delete")
async def delete_device(
    request: Request, session: SessionDep, user: ActiveUser, device_id: int
) -> Response:
    """Soft delete.

    A hard delete would either cascade away this device's audit history — the
    thing this application exists to keep — or fail on a foreign key. The row
    stays, excluded from every default query, and a later scan restores it
    rather than creating a duplicate.
    """
    device = await session.get(Device, device_id)
    if device is None:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    device.is_deleted = True
    device.deleted_at = datetime.now(UTC)
    await session.commit()

    logger.info("device %s soft-deleted by %r", device_id, user.username)
    return RedirectResponse("/devices", status_code=status.HTTP_303_SEE_OTHER)
