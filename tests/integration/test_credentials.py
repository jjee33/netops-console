"""Credential storage and the host key trust workflow.

The property this feature exists to provide: a credential is never offered to a
device whose identity has not been verified by a human. Everything else here is
in service of that.

Tests needing a real sshd are marked ``smoke`` and skipped by default — CI has
no SSH target. They were run against one during development; see
docs/MANUAL_VERIFICATION.md.
"""

from __future__ import annotations

import asyncssh
import httpx
import pytest
from sqlalchemy import func, select
from tests.conftest import csrf_token

from app.core.crypto import decrypt
from app.core.db import get_session_factory
from app.core.validation import ValidationError
from app.models import Credential, Device, SshHostKey
from app.modules.credentials import service

# Generated per test session rather than committed. A private key in a public
# repository is a bad pattern even when it is authorised nowhere: it trips every
# secret scanner for everyone who forks, and "this one is fine" is exactly the
# habit that eventually commits one that is not.
TEST_KEY: str = (
    asyncssh.generate_private_key("ssh-ed25519", comment="netops-test-fixture")
    .export_private_key("openssh")
    .decode()
)


async def _device(ip: str = "10.0.30.5") -> int:
    async with get_session_factory()() as session:
        device = Device(ip_address=ip, status="online")
        session.add(device)
        await session.commit()
        return device.id


async def _create(client: httpx.AsyncClient, **overrides: str) -> httpx.Response:
    token = await csrf_token(client, "/credentials")
    data = {
        "name": "Homelab key",
        "username": "netops",
        "auth_type": "ssh_key",
        "secret": TEST_KEY,
        "passphrase": "",
        "description": "",
        "csrf_token": token,
    }
    data.update(overrides)
    return await client.post("/credentials", data=data)


class TestStorage:
    async def test_a_key_is_stored_encrypted(self, auth_client: httpx.AsyncClient) -> None:
        assert (await _create(auth_client)).status_code == 303

        async with get_session_factory()() as session:
            credential = await session.scalar(select(Credential))

        assert credential is not None
        assert b"PRIVATE KEY" not in credential.secret_ciphertext
        assert TEST_KEY.encode() not in credential.secret_ciphertext
        # And it is genuinely recoverable, not merely mangled.
        assert decrypt(credential.secret_ciphertext) == TEST_KEY

    async def test_the_fingerprint_is_derived_and_shown(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        await _create(auth_client)
        async with get_session_factory()() as session:
            credential = await session.scalar(select(Credential))
        assert credential and credential.key_fingerprint
        assert credential.key_fingerprint.startswith("SHA256:")

        response = await auth_client.get("/credentials")
        assert credential.key_fingerprint in response.text

    async def test_the_secret_is_never_rendered(self, auth_client: httpx.AsyncClient) -> None:
        """The whole point. A page that shows the key back defeats storing it
        encrypted at all.

        Asserted against the key's own base64 body rather than the words
        "PRIVATE KEY", which legitimately appear in the form's placeholder.
        """
        await _create(auth_client)
        response = await auth_client.get("/credentials")

        for line in TEST_KEY.splitlines()[1:-1]:
            assert line.strip() not in response.text

    async def test_a_malformed_key_is_refused_at_entry(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """Rejected while the operator is looking at the form, rather than at 2am
        when an action fails."""
        response = await _create(auth_client, secret="not a key at all")
        assert response.status_code == 400
        assert "private key" in response.text.lower()

        async with get_session_factory()() as session:
            assert await session.scalar(select(func.count()).select_from(Credential)) == 0

    async def test_the_secret_is_not_echoed_back_on_error(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await _create(auth_client, name="", secret=TEST_KEY)
        # Rejected either by the form layer (422) or the service (400); both
        # prevent storage, and neither may echo the secret back.
        assert response.status_code in (400, 422)
        for line in TEST_KEY.splitlines()[1:-1]:
            assert line.strip() not in response.text

    async def test_duplicate_names_are_refused(self, auth_client: httpx.AsyncClient) -> None:
        assert (await _create(auth_client)).status_code == 303
        assert (await _create(auth_client)).status_code == 400

    async def test_a_password_credential_needs_no_key_parsing(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await _create(auth_client, auth_type="password", secret="a-device-password")
        assert response.status_code == 303

        async with get_session_factory()() as session:
            credential = await session.scalar(select(Credential))
        assert credential and credential.auth_type == "password"
        assert credential.key_fingerprint is None


class TestAssignment:
    async def test_assign_and_unassign(self, auth_client: httpx.AsyncClient) -> None:
        await _create(auth_client)
        device_id = await _device()

        async with get_session_factory()() as session:
            credential = await session.scalar(select(Credential))
            assert credential

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/credentials",
            data={"csrf_token": token, "credential_id": credential.id},
        )

        async with get_session_factory()() as session:
            assert len(await service.for_device(session, device_id)) == 1

        token = await csrf_token(auth_client, f"/devices/{device_id}")
        await auth_client.post(
            f"/devices/{device_id}/credentials",
            data={"csrf_token": token, "credential_id": credential.id, "unassign": "1"},
        )

        async with get_session_factory()() as session:
            assert await service.for_device(session, device_id) == []

    async def test_assigning_twice_is_harmless(self, auth_client: httpx.AsyncClient) -> None:
        await _create(auth_client)
        device_id = await _device()
        async with get_session_factory()() as session:
            credential = await session.scalar(select(Credential))
            assert credential
            await service.assign(session, device_id, credential.id)
            await service.assign(session, device_id, credential.id)
            assert len(await service.for_device(session, device_id)) == 1


class TestHostKeyTrust:
    async def test_a_device_starts_untrusted(self, migrated) -> None:
        device_id = await _device()
        async with get_session_factory()() as session:
            assert await service.trusted_key_for(session, device_id) is None

    async def test_trusting_records_who_and_when(self, migrated) -> None:
        from app.modules.ssh.client import PresentedKey

        device_id = await _device()
        key = PresentedKey("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAI", "SHA256:abc")

        async with get_session_factory()() as session:
            device = await session.get(Device, device_id)
            assert device
            await service.trust(session, device, key, user_id=None, username="admin")

            record = await session.scalar(select(SshHostKey))
            assert record
            assert record.fingerprint == "SHA256:abc"
            assert record.trusted_by_snapshot == "admin"
            assert record.trusted_at is not None

    async def test_trusting_the_same_key_twice_is_idempotent(self, migrated) -> None:
        from app.modules.ssh.client import PresentedKey

        device_id = await _device()
        key = PresentedKey("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAI", "SHA256:abc")

        async with get_session_factory()() as session:
            device = await session.get(Device, device_id)
            assert device
            await service.trust(session, device, key, user_id=None, username="admin")
            await service.trust(session, device, key, user_id=None, username="admin")
            assert await session.scalar(select(func.count()).select_from(SshHostKey)) == 1

    async def test_revoking_returns_the_device_to_untrusted(self, migrated) -> None:
        """Needed when a device is legitimately rebuilt: the next connection goes
        back through review rather than being accepted silently."""
        from app.modules.ssh.client import PresentedKey

        device_id = await _device()
        key = PresentedKey("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAI", "SHA256:abc")

        async with get_session_factory()() as session:
            device = await session.get(Device, device_id)
            assert device
            await service.trust(session, device, key, user_id=None, username="admin")
            assert await service.trusted_key_for(session, device_id) is not None

            assert await service.revoke_host_key(session, device_id) == 1
            assert await service.trusted_key_for(session, device_id) is None

    async def test_the_device_page_says_when_a_device_is_unverified(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        device_id = await _device()
        response = await auth_client.get(f"/devices/{device_id}")
        assert "identity has not been verified" in response.text


class TestSshActionsRequireTrust:
    async def test_an_ssh_action_is_refused_without_a_credential(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        import ipaddress

        from app.models import ActionDefinition
        from app.modules.actions import service as actions_service

        device_id = await _device("10.0.30.5")

        async with get_session_factory()() as session:
            definition = ActionDefinition(
                name="Remote uptime",
                execution_type="ssh",
                argv_template=["uptime"],
                param_schema={},
                timeout_seconds=10,
            )
            session.add(definition)
            await session.commit()

            device = await session.get(Device, device_id)
            assert device

            execution = await actions_service.execute(
                session,
                definition,
                device,
                {},
                [ipaddress.IPv4Network("10.0.0.0/8")],
                user_id=None,
                username="admin",
                client_ip="127.0.0.1",
            )

        assert execution.status == "rejected"
        assert "No credential is assigned" in (execution.stderr or "")


class TestAccessControl:
    async def test_the_credentials_page_requires_authentication(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/credentials")
        assert response.status_code == 303

    async def test_creating_a_credential_requires_a_csrf_token(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await auth_client.post(
            "/credentials", data={"name": "x", "username": "y", "secret": TEST_KEY}
        )
        assert response.status_code == 403

        async with get_session_factory()() as session:
            assert await session.scalar(select(func.count()).select_from(Credential)) == 0


class TestServiceValidation:
    @pytest.mark.parametrize(
        ("field", "value"),
        [("name", ""), ("username", ""), ("secret", ""), ("auth_type", "telnet")],
    )
    async def test_required_fields(self, migrated, field: str, value: str) -> None:
        kwargs = {
            "name": "n",
            "username": "u",
            "auth_type": "password",
            "secret": "s",
        }
        kwargs[field] = value

        async with get_session_factory()() as session:
            with pytest.raises(ValidationError):
                await service.create(session, **kwargs)  # type: ignore[arg-type]

    async def test_an_implausibly_large_secret_is_refused(self, migrated) -> None:
        async with get_session_factory()() as session:
            with pytest.raises(ValidationError, match="implausibly large"):
                await service.create(
                    session,
                    name="n",
                    username="u",
                    auth_type="password",
                    secret="x" * 200_000,
                )
