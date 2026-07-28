"""Credential management and the host key trust workflow.

No route in this module returns a secret. Creation accepts one, encrypts it, and
never reads it back; the list shows a name, username and fingerprint, which is
enough to tell two credentials apart and useless for anything else.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import RedirectResponse, Response

from app.core.templating import render
from app.core.validation import ValidationError
from app.models import Credential, Device
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.credentials import service
from app.modules.ssh import client as ssh_client

logger = logging.getLogger("netops.credentials")

router = APIRouter(tags=["credentials"])


@router.get("/credentials")
async def credential_list(request: Request, session: SessionDep, user: ActiveUser) -> Response:
    return render(
        request,
        "credentials.html",
        {"credentials": await service.list_all(session), "error": None, "form": {}},
    )


@router.post("/credentials")
async def create_credential(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    name: Annotated[str, Form()],
    username: Annotated[str, Form()],
    secret: Annotated[str, Form()],
    auth_type: Annotated[str, Form()] = "ssh_key",
    passphrase: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
) -> Response:
    try:
        await service.create(
            session,
            name=name,
            username=username,
            auth_type=auth_type,
            secret=secret,
            passphrase=passphrase or None,
            description=description,
        )
    except ValidationError as exc:
        return render(
            request,
            "credentials.html",
            {
                "credentials": await service.list_all(session),
                "error": str(exc),
                # The secret is deliberately not echoed back into the form.
                "form": {
                    "name": name,
                    "username": username,
                    "auth_type": auth_type,
                    "description": description,
                },
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    logger.info("credential %r created by %r", name, user.username)
    return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/credentials/{credential_id}/delete")
async def delete_credential(
    request: Request, session: SessionDep, user: ActiveUser, credential_id: int
) -> Response:
    credential = await session.get(Credential, credential_id)
    if credential is None:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    await session.delete(credential)
    await session.commit()

    logger.info("credential %r deleted by %r", credential.name, user.username)
    return RedirectResponse("/credentials", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/devices/{device_id}/credentials")
async def assign_credential(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    device_id: int,
    credential_id: Annotated[int, Form()],
    unassign: Annotated[str | None, Form()] = None,
) -> Response:
    device = await session.get(Device, device_id)
    if device is None or device.is_deleted:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    if unassign is not None:
        await service.unassign(session, device_id, credential_id)
    else:
        await service.assign(session, device_id, credential_id)

    return RedirectResponse(f"/devices/{device_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/devices/{device_id}/hostkey/probe")
async def probe_host_key(
    request: Request, session: SessionDep, user: ActiveUser, device_id: int
) -> Response:
    """Read the device's host key and show it for review.

    Nothing is trusted here. This exists so an operator can compare a
    fingerprint against the device itself before deciding.
    """
    device = await session.get(Device, device_id)
    if device is None or device.is_deleted:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    try:
        key = await service.probe(device)
    except ssh_client.SshError as exc:
        return render(
            request,
            "partials/host_key_review.html",
            {"device": device, "key": None, "error": str(exc)},
        )

    return render(
        request,
        "partials/host_key_review.html",
        {"device": device, "key": key, "error": None},
    )


@router.post("/devices/{device_id}/hostkey/trust")
async def trust_host_key(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    device_id: int,
    key_type: Annotated[str, Form()],
    key_base64: Annotated[str, Form()],
    fingerprint: Annotated[str, Form()],
) -> Response:
    """Record the operator's decision to trust a specific key.

    The key is re-read from the device rather than taken from the form. A
    submitted fingerprint is a claim about what was reviewed, not evidence of
    what the device presents — trusting the form value would mean trusting
    whatever the browser sent.
    """
    device = await session.get(Device, device_id)
    if device is None or device.is_deleted:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    try:
        presented = await service.probe(device)
    except ssh_client.SshError as exc:
        return render(
            request,
            "partials/host_key_review.html",
            {"device": device, "key": None, "error": str(exc)},
        )

    if presented.fingerprint != fingerprint:
        # The device is answering with something other than what was reviewed.
        # Refuse and show the new value rather than trusting either.
        logger.warning(
            "host key changed between review and trust for device %s (%s -> %s)",
            device_id,
            fingerprint,
            presented.fingerprint,
        )
        return render(
            request,
            "partials/host_key_review.html",
            {
                "device": device,
                "key": presented,
                "error": (
                    "The device presented a different key than the one you reviewed. "
                    "Nothing was trusted. Review the new fingerprint below."
                ),
            },
            status_code=status.HTTP_409_CONFLICT,
        )

    await service.trust(session, device, presented, user_id=user.id, username=user.username)

    return RedirectResponse(f"/devices/{device_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/devices/{device_id}/hostkey/revoke")
async def revoke_host_key(
    request: Request, session: SessionDep, user: ActiveUser, device_id: int
) -> Response:
    device = await session.get(Device, device_id)
    if device is None:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    removed = await service.revoke_host_key(session, device_id)
    logger.warning("%d host key(s) revoked for device %s by %r", removed, device_id, user.username)

    return RedirectResponse(f"/devices/{device_id}", status_code=status.HTTP_303_SEE_OTHER)
