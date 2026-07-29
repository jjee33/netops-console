"""Action definition and execution.

The two properties that matter: an unsafe definition cannot be saved, and every
execution attempt is recorded whether or not it ran.
"""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import func, select
from tests.conftest import csrf_token

from app.core.db import get_session_factory
from app.models import ActionDefinition, ActionExecution, Device


async def _define(client: httpx.AsyncClient, **overrides: object) -> httpx.Response:
    token = await csrf_token(client, "/actions")
    data: dict[str, object] = {
        "name": "Show routes",
        "description": "Display the routing table",
        "execution_type": "local",
        "argv_template": json.dumps(["ip", "route", "show"]),
        "param_schema": "",
        "timeout_seconds": "10",
        "applicable_types": "",
        "csrf_token": token,
    }
    data.update(overrides)
    return await client.post("/actions", data=data)


async def _device(ip: str = "10.0.30.5", device_type: str | None = None) -> int:
    async with get_session_factory()() as session:
        device = Device(ip_address=ip, status="online", device_type=device_type)
        session.add(device)
        await session.commit()
        return device.id


async def _allow(client: httpx.AsyncClient, cidrs: str = "10.0.0.0/8") -> None:
    token = await csrf_token(client, "/settings")
    response = await client.post(
        "/settings",
        data={
            "allowed_cidrs": cidrs,
            "max_scan_hosts": "1024",
            "max_concurrent_scans": "1",
            "max_concurrent_executions": "4",
            "retention_days": "90",
            "csrf_token": token,
        },
    )
    assert response.status_code == 200


async def _definitions() -> list[ActionDefinition]:
    async with get_session_factory()() as session:
        return list(await session.scalars(select(ActionDefinition)))


async def _executions() -> list[ActionExecution]:
    async with get_session_factory()() as session:
        return list(await session.scalars(select(ActionExecution).order_by(ActionExecution.id)))


class TestDefiningActions:
    async def test_a_valid_local_action_is_saved(self, auth_client: httpx.AsyncClient) -> None:
        assert (await _define(auth_client)).status_code == 303
        definitions = await _definitions()
        assert len(definitions) == 1
        assert definitions[0].argv_template == ["ip", "route", "show"]

    @pytest.mark.parametrize("program", ["bash", "sh", "python3", "awk", "sudo", "find"])
    async def test_programs_that_run_arbitrary_commands_are_refused(
        self, auth_client: httpx.AsyncClient, program: str
    ) -> None:
        """Allowing any of these would make the argv discipline pointless — each
        one takes a command as an argument."""
        response = await _define(auth_client, argv_template=json.dumps([program, "-c", "id"]))
        assert response.status_code == 400
        assert await _definitions() == []

    async def test_a_program_outside_the_allowlist_is_refused(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await _define(auth_client, argv_template=json.dumps(["curl", "http://x"]))
        assert response.status_code == 400
        assert "not an allowed program" in response.text

    async def test_an_ssh_parameter_without_a_pattern_is_refused(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """The rule the SSH path rests on, enforced at definition time so an
        unsafe action cannot be stored and run later."""
        response = await _define(
            auth_client,
            execution_type="ssh",
            argv_template=json.dumps(["docker", "restart", "{container}"]),
            param_schema=json.dumps({"container": {"type": "string"}}),
        )
        assert response.status_code == 400
        assert "needs a pattern" in response.text
        assert await _definitions() == []

    async def test_an_ssh_action_with_a_pattern_is_accepted(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await _define(
            auth_client,
            name="Restart container",
            execution_type="ssh",
            argv_template=json.dumps(["docker", "restart", "{container}"]),
            param_schema=json.dumps(
                {"container": {"type": "string", "pattern": "^[a-zA-Z0-9_.-]{1,64}$"}}
            ),
        )
        assert response.status_code == 303

    async def test_a_pattern_matching_everything_is_refused(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await _define(
            auth_client,
            execution_type="ssh",
            argv_template=json.dumps(["docker", "restart", "{container}"]),
            param_schema=json.dumps({"container": {"type": "string", "pattern": ".*"}}),
        )
        assert response.status_code == 400
        assert "matches anything" in response.text

    async def test_an_embedded_placeholder_is_refused(self, auth_client: httpx.AsyncClient) -> None:
        response = await _define(
            auth_client,
            argv_template=json.dumps(["ip", "route", "show", "dev={iface}"]),
            param_schema=json.dumps({"iface": {"type": "string"}}),
        )
        assert response.status_code == 400
        assert "embeds a parameter" in response.text

    async def test_malformed_json_is_explained_not_crashed(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await _define(auth_client, argv_template="[not json")
        assert response.status_code == 400
        assert "not valid JSON" in response.text

    async def test_an_excessive_timeout_is_refused(self, auth_client: httpx.AsyncClient) -> None:
        response = await _define(auth_client, timeout_seconds="99999")
        assert response.status_code in (400, 422)


class TestExecution:
    async def _create_and_get(self, client: httpx.AsyncClient, **overrides: object) -> int:
        assert (await _define(client, **overrides)).status_code == 303
        return (await _definitions())[0].id

    async def test_a_local_action_runs_and_is_recorded(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _allow(auth_client)
        action_id = await self._create_and_get(auth_client)
        device_id = await _device()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        response = await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}", data={"csrf_token": token}
        )

        assert response.status_code == 200
        executions = await _executions()
        assert len(executions) == 1
        assert executions[0].status in ("success", "failed")
        assert executions[0].command_preview
        assert "ip route show" in executions[0].command_preview

    async def test_a_device_outside_the_allowed_ranges_is_refused(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _allow(auth_client, "192.168.0.0/16")
        action_id = await self._create_and_get(auth_client)
        device_id = await _device("10.0.30.5")

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}", data={"csrf_token": token}
        )

        executions = await _executions()
        assert executions[0].status == "rejected"
        assert "outside the currently allowed ranges" in (executions[0].stderr or "")

    async def test_ssh_actions_are_refused_without_an_assigned_credential(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """The gate before the gate. A device with no credential cannot be
        reached at all, so the host key check is never even the thing that
        stops it."""
        await _allow(auth_client)
        assert (
            await _define(
                auth_client,
                name="Remote uptime",
                execution_type="ssh",
                argv_template=json.dumps(["uptime"]),
                param_schema="",
            )
        ).status_code == 303

        action_id = (await _definitions())[0].id
        device_id = await _device()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}", data={"csrf_token": token}
        )

        executions = await _executions()
        assert executions[0].status == "rejected"
        assert "No credential is assigned" in (executions[0].stderr or "")

    async def test_a_disabled_action_does_not_run(self, auth_client: httpx.AsyncClient) -> None:
        await _allow(auth_client)
        action_id = await self._create_and_get(auth_client)
        device_id = await _device()

        token = await csrf_token(auth_client, "/actions")
        await auth_client.post(f"/actions/{action_id}/toggle", data={"csrf_token": token})

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}", data={"csrf_token": token}
        )

        assert (await _executions())[0].status == "rejected"

    async def test_a_parameter_failing_its_pattern_is_refused(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _allow(auth_client)
        action_id = await self._create_and_get(
            auth_client,
            name="Route for device",
            argv_template=json.dumps(["ip", "route", "get", "{target}"]),
            param_schema=json.dumps({"target": {"type": "string", "pattern": r"^[0-9.]{7,15}$"}}),
        )
        device_id = await _device()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}",
            data={"csrf_token": token, "target": "10.0.0.1; id"},
        )

        executions = await _executions()
        assert executions[0].status == "rejected"
        assert "does not match" in (executions[0].stderr or "")

    async def test_extra_form_fields_cannot_smuggle_arguments(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """Only names in the schema are substituted; anything else is ignored."""
        await _allow(auth_client)
        action_id = await self._create_and_get(auth_client)
        device_id = await _device()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}",
            data={"csrf_token": token, "evil": "--force", "argv": "rm -rf /"},
        )

        preview = (await _executions())[0].command_preview or ""
        assert preview.endswith("ip route show")
        assert "--force" not in preview
        assert "rm -rf" not in preview

    async def test_secret_parameters_are_masked_in_the_record(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _allow(auth_client)
        action_id = await self._create_and_get(
            auth_client,
            name="With secret",
            argv_template=json.dumps(["ip", "route", "get", "{token}"]),
            param_schema=json.dumps(
                {"token": {"type": "string", "pattern": "^[a-z0-9]+$", "secret": True}}
            ),
        )
        device_id = await _device()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}",
            data={"csrf_token": token, "token": "supersecret"},
        )

        execution = (await _executions())[0]
        assert (execution.params_redacted or {}).get("token") == "[redacted]"

        # And the same value must not survive in the command preview, which is
        # stored in the database and rendered in the audit log.
        assert "supersecret" not in (execution.command_preview or "")
        assert "[redacted]" in (execution.command_preview or "")

    async def test_a_secret_parameter_does_not_reach_the_audit_log(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _allow(auth_client)
        action_id = await self._create_and_get(
            auth_client,
            name="With secret",
            argv_template=json.dumps(["ip", "route", "get", "{token}"]),
            param_schema=json.dumps(
                {"token": {"type": "string", "pattern": "^[a-z0-9]+$", "secret": True}}
            ),
        )
        device_id = await _device()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}",
            data={"csrf_token": token, "token": "supersecret"},
        )

        audit = await auth_client.get("/audit")
        assert "supersecret" not in audit.text


class TestApplicability:
    async def test_an_action_scoped_to_a_type_is_hidden_elsewhere(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """A switch command should not be one click away on a NAS."""
        await _define(auth_client, name="Switch only", applicable_types="switch")

        switch = await _device("10.0.30.10", device_type="switch")
        nas = await _device("10.0.30.11", device_type="nas")

        assert "Switch only" in (await auth_client.get(f"/devices/{switch}")).text
        assert "Switch only" not in (await auth_client.get(f"/devices/{nas}")).text

    async def test_an_unscoped_action_appears_everywhere(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _define(auth_client, name="Everywhere")
        device_id = await _device("10.0.30.12", device_type="nas")
        assert "Everywhere" in (await auth_client.get(f"/devices/{device_id}")).text


class TestHistoryAndDeletion:
    async def test_deleting_a_definition_keeps_its_executions(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _allow(auth_client)
        assert (await _define(auth_client)).status_code == 303
        action_id = (await _definitions())[0].id
        device_id = await _device()

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/actions/{action_id}", data={"csrf_token": token}
        )

        token = await csrf_token(auth_client, "/actions")
        await auth_client.post(f"/actions/{action_id}/delete", data={"csrf_token": token})

        async with get_session_factory()() as session:
            assert await session.scalar(select(func.count()).select_from(ActionDefinition)) == 0
            assert await session.scalar(select(func.count()).select_from(ActionExecution)) == 1

        # The snapshot is why the surviving row is still readable.
        assert (await _executions())[0].action_name_snapshot == "Show routes"


class TestAccessControl:
    @pytest.mark.parametrize("path", ["/actions"])
    async def test_pages_require_authentication(self, client: httpx.AsyncClient, path: str) -> None:
        response = await client.get(path)
        assert response.status_code == 303

    async def test_defining_an_action_requires_a_csrf_token(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await auth_client.post("/actions", data={"name": "x"})
        assert response.status_code == 403
        assert await _definitions() == []
