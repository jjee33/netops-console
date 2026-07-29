"""Action library and execution endpoints.

The execution endpoint takes an action id and a form of parameters. There is no
field anywhere that carries a command — the server resolves what runs from the
stored definition.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import RedirectResponse, Response

from app.core.requests import client_ip
from app.core.templating import render
from app.core.validation import ValidationError
from app.models import ActionDefinition, Device
from app.modules.actions import service
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.settings import service as settings_service

logger = logging.getLogger("netops.actions")

router = APIRouter(tags=["actions"])


def _parse_json_field(raw: str, label: str, fallback: Any) -> Any:
    raw = raw.strip()
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{label} is not valid JSON: {exc.msg} (line {exc.lineno}).") from exc


@router.get("/actions")
async def action_library(request: Request, session: SessionDep, user: ActiveUser) -> Response:
    return render(
        request,
        "actions.html",
        {
            "definitions": await service.list_definitions(session),
            "error": None,
            "form": {},
        },
    )


@router.post("/actions")
async def create_action(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    name: Annotated[str, Form()],
    argv_template: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    execution_type: Annotated[str, Form()] = "local",
    param_schema: Annotated[str, Form()] = "",
    timeout_seconds: Annotated[int, Form()] = 30,
    confirmation_required: Annotated[str | None, Form()] = None,
    elevated_required: Annotated[str | None, Form()] = None,
    applicable_types: Annotated[str, Form()] = "",
) -> Response:
    form = {
        "name": name,
        "description": description,
        "execution_type": execution_type,
        "argv_template": argv_template,
        "param_schema": param_schema,
        "timeout_seconds": timeout_seconds,
        "applicable_types": applicable_types,
    }

    try:
        template = _parse_json_field(argv_template, "The command template", None)
        if template is None:
            raise ValidationError(
                "The command template is required, as a JSON list — for example "
                '["ip", "route", "show"].'
            )
        parsed_schema = _parse_json_field(param_schema, "The parameter schema", {})

        service.validate_definition(
            name=name,
            execution_type=execution_type,
            argv_template=template,
            param_schema=parsed_schema,
            timeout_seconds=timeout_seconds,
        )
    except ValidationError as exc:
        return render(
            request,
            "actions.html",
            {
                "definitions": await service.list_definitions(session),
                "error": str(exc),
                "form": form,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    definition = ActionDefinition(
        name=name.strip(),
        description=description.strip() or None,
        execution_type=execution_type,
        argv_template=template,
        param_schema=parsed_schema,
        timeout_seconds=timeout_seconds,
        confirmation_required=confirmation_required is not None,
        elevated_required=elevated_required is not None,
        applicable_types=[entry.strip() for entry in applicable_types.split(",") if entry.strip()],
    )
    session.add(definition)
    await session.commit()

    logger.info("action %r created by %r", definition.name, user.username)
    return RedirectResponse("/actions", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/actions/{action_id}/toggle")
async def toggle_action(
    request: Request, session: SessionDep, user: ActiveUser, action_id: int
) -> Response:
    definition = await session.get(ActionDefinition, action_id)
    if definition is None:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    definition.enabled = not definition.enabled
    await session.commit()

    logger.info(
        "action %r %s by %r",
        definition.name,
        "enabled" if definition.enabled else "disabled",
        user.username,
    )
    return RedirectResponse("/actions", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/actions/{action_id}/delete")
async def delete_action(
    request: Request, session: SessionDep, user: ActiveUser, action_id: int
) -> Response:
    definition = await session.get(ActionDefinition, action_id)
    if definition is None:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    # The definition goes; its execution history does not. The foreign key is
    # SET NULL and the name is snapshotted on every row.
    await session.delete(definition)
    await session.commit()

    logger.info("action %r deleted by %r", definition.name, user.username)
    return RedirectResponse("/actions", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/devices/{device_id}/actions/{action_id}")
async def run_action(
    request: Request, session: SessionDep, user: ActiveUser, device_id: int, action_id: int
) -> Response:
    device = await session.get(Device, device_id)
    if device is None or device.is_deleted:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    definition = await session.get(ActionDefinition, action_id)
    if definition is None:
        return render(request, "not_found.html", {}, status_code=status.HTTP_404_NOT_FOUND)

    # Parameters arrive as ordinary form fields named after the schema. Anything
    # not in the schema is ignored by build_argv, so extra fields cannot smuggle
    # in an argument.
    form = await request.form()
    values = {
        key: value for key, value in form.items() if key != "csrf_token" and isinstance(value, str)
    }

    settings = await settings_service.load(session)

    execution = await service.execute(
        session,
        definition,
        device,
        values,
        settings.allowed_networks,
        user_id=user.id,
        username=user.username,
        client_ip=client_ip(request),
    )

    # Same reasoning as diagnostics: the path that creates the volume is the
    # one that pays for cleaning it up.
    from app.core.retention import prune

    await prune(session, settings.retention_days)

    return render(
        request,
        "partials/action_result.html",
        {"execution": execution, "definition": definition, "device": device},
    )
