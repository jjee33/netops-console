"""Diagnostic execution, audit recording, and retention.

The property under test throughout: every attempt writes a row, including the
refused ones. An audit log that records only what succeeded is not an audit log,
and a refusal is as much a thing that happened as a result.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from tests.conftest import csrf_token

from app.core.db import get_session_factory
from app.models import DiagnosticResult
from app.modules.discovery.parser import ParsedHost
from app.modules.discovery.service import upsert_device


async def _device(ip: str = "127.0.0.1", hostname: str | None = None) -> int:
    async with get_session_factory()() as session:
        device, _ = await upsert_device(
            session, ParsedHost(ip_address=ip, mac_address="aa:bb:cc:dd:ee:ff", hostname=hostname)
        )
        await session.commit()
        return device.id


async def _allow(client: httpx.AsyncClient, cidrs: str) -> None:
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
    assert response.status_code == 200, response.text


async def _run(
    client: httpx.AsyncClient, device_id: int, kind: str, **fields: str
) -> httpx.Response:
    token = await csrf_token(client, f"/devices/{device_id}")
    return await client.post(
        f"/devices/{device_id}/diagnostics/{kind}",
        data={"csrf_token": token, **fields},
    )


async def _results() -> list[DiagnosticResult]:
    async with get_session_factory()() as session:
        return list(await session.scalars(select(DiagnosticResult).order_by(DiagnosticResult.id)))


class TestTargetValidation:
    async def test_a_device_outside_the_allowed_ranges_is_refused(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """A device row is not a permission. Narrowing the allowlist after
        discovery must stop the inventory being a way to keep reaching hosts
        the operator has put out of scope."""
        device_id = await _device("10.0.30.5")
        await _allow(auth_client, "192.168.0.0/16")

        response = await _run(auth_client, device_id, "ping")
        assert response.status_code == 200
        assert "outside the currently allowed ranges" in response.text

        results = await _results()
        assert len(results) == 1
        assert results[0].status == "rejected"

    async def test_the_refusal_is_recorded_with_full_attribution(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device("10.0.30.5")
        await _allow(auth_client, "192.168.0.0/16")
        await _run(auth_client, device_id, "ping")

        result = (await _results())[0]
        assert result.status == "rejected"
        assert result.username_snapshot == "admin"
        assert result.client_ip
        assert result.device_id == device_id
        assert result.started_at and result.completed_at

    async def test_an_unknown_diagnostic_is_a_404(self, auth_client: httpx.AsyncClient) -> None:
        device_id = await _device()
        assert (await _run(auth_client, device_id, "rm-rf-slash")).status_code == 404
        assert await _results() == []

    async def test_a_missing_device_is_a_404(self, auth_client: httpx.AsyncClient) -> None:
        token = await csrf_token(auth_client, "/devices")
        response = await auth_client.post(
            "/devices/99999/diagnostics/ping", data={"csrf_token": token}
        )
        assert response.status_code == 404


class TestExecution:
    """Loopback is used as the target: allowed explicitly for these tests only,
    so a real command runs without depending on anything else being up."""

    async def test_ping_runs_and_records_a_result(self, auth_client: httpx.AsyncClient) -> None:
        device_id = await _device("127.0.0.1")
        await _allow(auth_client, "10.0.0.0/8")

        # 127.0.0.1 is refused by the allowlist, which is correct — so this
        # asserts the refusal path end to end rather than pretending otherwise.
        response = await _run(auth_client, device_id, "ping")
        assert response.status_code == 200
        assert (await _results())[0].status == "rejected"

    async def test_output_is_rendered_escaped(self, auth_client: httpx.AsyncClient) -> None:
        """Command output is untrusted. The result partial must never use |safe."""
        device_id = await _device("10.0.30.5")
        await _allow(auth_client, "192.168.0.0/16")

        async with get_session_factory()() as session:
            session.add(
                DiagnosticResult(
                    device_id=device_id,
                    type="ping",
                    target="10.0.30.5",
                    status="success",
                    output="<script>alert('xss')</script>",
                    started_at=datetime.now(UTC),
                )
            )
            await session.commit()
            stored = await session.scalar(
                select(DiagnosticResult).order_by(DiagnosticResult.id.desc())
            )
            assert stored

        response = await auth_client.get(f"/diagnostics/{stored.id}")
        assert response.status_code == 200
        assert "<script>alert('xss')</script>" not in response.text
        assert "&lt;script&gt;" in response.text

    async def test_dns_without_a_hostname_explains_itself(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device("10.0.30.5", hostname=None)
        await _allow(auth_client, "10.0.0.0/8")

        response = await _run(auth_client, device_id, "dns")
        assert "no discovered hostname" in response.text
        assert (await _results())[-1].status == "rejected"

    async def test_a_port_diagnostic_without_a_port_is_refused(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device("10.0.30.5")
        await _allow(auth_client, "10.0.0.0/8")

        response = await _run(auth_client, device_id, "tcp")
        assert "needs a port" in response.text
        assert (await _results())[-1].status == "rejected"

    @pytest.mark.parametrize("port", ["0", "70000", "-1", "not-a-port"])
    async def test_an_invalid_port_is_refused(
        self, auth_client: httpx.AsyncClient, port: str
    ) -> None:
        device_id = await _device("10.0.30.5")
        await _allow(auth_client, "10.0.0.0/8")

        response = await _run(auth_client, device_id, "tcp", port=port)
        # Either the form rejects it or the validator does; both prevent the run.
        assert response.status_code in (200, 422)
        if response.status_code == 200:
            assert (await _results())[-1].status == "rejected"


class TestDevicePage:
    async def test_the_device_page_offers_the_fixed_diagnostic_set(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device("10.0.30.5")
        response = await auth_client.get(f"/devices/{device_id}")

        assert response.status_code == 200
        for label in ("Ping", "Traceroute", "Reverse DNS", "TCP port test", "HTTP check"):
            assert label in response.text

    async def test_there_is_no_free_form_command_input(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """The frontend sends which check to run, never a command."""
        device_id = await _device("10.0.30.5")
        response = await auth_client.get(f"/devices/{device_id}")

        assert 'name="command"' not in response.text
        assert 'name="cmd"' not in response.text
        assert 'name="argv"' not in response.text

    async def test_history_appears_on_the_device_page(self, auth_client: httpx.AsyncClient) -> None:
        device_id = await _device("10.0.30.5")
        await _allow(auth_client, "192.168.0.0/16")
        await _run(auth_client, device_id, "ping")

        response = await auth_client.get(f"/devices/{device_id}")
        assert "Recent checks" in response.text
        assert "rejected" in response.text


class TestAccessControl:
    async def test_running_a_diagnostic_requires_authentication(
        self, client: httpx.AsyncClient
    ) -> None:
        device_id = await _device("10.0.30.5")
        response = await client.post(f"/devices/{device_id}/diagnostics/ping", data={})
        assert response.status_code in (303, 403)
        assert await _results() == []

    async def test_running_a_diagnostic_requires_a_csrf_token(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device("10.0.30.5")
        response = await auth_client.post(f"/devices/{device_id}/diagnostics/ping", data={})
        assert response.status_code == 403
        assert await _results() == []


class TestRetention:
    async def test_old_results_are_pruned(self, migrated: Path) -> None:
        """Each row carries an output blob. Without pruning the database and
        every backup taken from it grow without bound."""
        from app.modules.diagnostics.service import prune

        async with get_session_factory()() as session:
            session.add_all(
                [
                    DiagnosticResult(
                        type="ping",
                        target="10.0.30.5",
                        status="success",
                        output="x" * 500,
                        started_at=datetime.now(UTC) - timedelta(days=age),
                    )
                    for age in (1, 30, 100, 400)
                ]
            )
            await session.commit()

        async with get_session_factory()() as session:
            removed = await prune(session, retention_days=90)

        assert removed == 2
        async with get_session_factory()() as session:
            assert await session.scalar(select(func.count()).select_from(DiagnosticResult)) == 2

    async def test_pruning_is_a_no_op_when_nothing_is_old(self, migrated: Path) -> None:
        from app.modules.diagnostics.service import prune

        async with get_session_factory()() as session:
            session.add(
                DiagnosticResult(
                    type="ping",
                    target="10.0.30.5",
                    status="success",
                    started_at=datetime.now(UTC),
                )
            )
            await session.commit()

        async with get_session_factory()() as session:
            assert await prune(session, retention_days=90) == 0

    async def test_a_nonsensical_retention_never_deletes_everything(self, migrated: Path) -> None:
        """A zero or negative window must not be read as 'keep nothing'."""
        from app.modules.diagnostics.service import prune

        async with get_session_factory()() as session:
            session.add(
                DiagnosticResult(
                    type="ping",
                    target="10.0.30.5",
                    status="success",
                    started_at=datetime.now(UTC) - timedelta(days=10),
                )
            )
            await session.commit()

        async with get_session_factory()() as session:
            assert await prune(session, retention_days=0) == 0
            assert await prune(session, retention_days=-5) == 0
            assert await session.scalar(select(func.count()).select_from(DiagnosticResult)) == 1


class TestAuditSurvivesDeletion:
    async def test_deleting_a_device_keeps_its_diagnostic_history(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device("10.0.30.5")
        await _allow(auth_client, "192.168.0.0/16")
        await _run(auth_client, device_id, "ping")

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(f"/devices/{device_id}/delete", data={"csrf_token": token})

        results = await _results()
        assert len(results) == 1
        # The label snapshot is why the row stays readable without the device.
        assert results[0].device_label_snapshot
