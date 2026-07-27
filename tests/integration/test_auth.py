"""Login, session, and password change.

Weighted toward the failure paths. A login form that accepts the right password
is easy; one that reveals nothing when given the wrong one is the actual
requirement.
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select
from tests.conftest import TEST_PASSWORD, csrf_token

from app.core.db import get_session_factory
from app.models import User


async def _login(client: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    token = await csrf_token(client, "/login")
    return await client.post(
        "/login",
        data={"username": username, "password": password, "next": "/", "csrf_token": token},
    )


class TestAccessControl:
    @pytest.mark.parametrize("path", ["/", "/settings", "/account/password"])
    async def test_protected_pages_redirect_when_unauthenticated(
        self, client: httpx.AsyncClient, path: str
    ) -> None:
        response = await client.get(path)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")

    async def test_authenticated_user_reaches_the_dashboard(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await auth_client.get("/")
        assert response.status_code == 200
        assert "Dashboard" in response.text

    async def test_logout_ends_the_session(self, auth_client: httpx.AsyncClient) -> None:
        token = await csrf_token(auth_client, "/settings")
        response = await auth_client.post("/logout", data={"csrf_token": token})
        assert response.status_code == 303

        after = await auth_client.get("/")
        assert after.status_code == 303
        assert after.headers["location"].startswith("/login")


class TestCredentialDisclosure:
    async def test_wrong_password_and_unknown_user_are_indistinguishable(
        self, client: httpx.AsyncClient
    ) -> None:
        """The response must not reveal whether an account exists. Identical
        status and identical message, or the endpoint is a username oracle."""
        wrong = await _login(client, "admin", "definitely-not-the-password")
        unknown = await _login(client, "no-such-account", "definitely-not-the-password")

        assert wrong.status_code == unknown.status_code == 401
        assert "Invalid username or password." in wrong.text
        assert "Invalid username or password." in unknown.text

    @pytest.mark.parametrize("leak", ["no such user", "unknown user", "incorrect password"])
    async def test_error_never_names_the_specific_failure(
        self, client: httpx.AsyncClient, leak: str
    ) -> None:
        response = await _login(client, "admin", "wrong")
        assert leak.lower() not in response.text.lower()

    async def test_disabled_account_gets_the_generic_message(
        self, client: httpx.AsyncClient
    ) -> None:
        async with get_session_factory()() as session:
            user = await session.scalar(select(User).where(User.username == "admin"))
            assert user
            user.is_active = False
            await session.commit()

        response = await _login(client, "admin", TEST_PASSWORD)
        assert response.status_code == 401
        assert "Invalid username or password." in response.text
        assert "disabled" not in response.text.lower()


class TestLockout:
    async def test_account_locks_after_repeated_failures(self, client: httpx.AsyncClient) -> None:
        for _ in range(5):
            await _login(client, "admin", "wrong")

        async with get_session_factory()() as session:
            user = await session.scalar(select(User).where(User.username == "admin"))
            assert user
            assert user.failed_login_count >= 5
            assert user.locked_until is not None

    async def test_correct_password_is_refused_while_locked(
        self, client: httpx.AsyncClient
    ) -> None:
        """The lockout has to hold against the real password too, or it only
        slows down an attacker who was going to fail anyway."""
        for _ in range(5):
            await _login(client, "admin", "wrong")

        response = await _login(client, "admin", TEST_PASSWORD)
        assert response.status_code == 401
        assert "Too many failed attempts" in response.text

    async def test_successful_login_clears_the_failure_counter(
        self, client: httpx.AsyncClient
    ) -> None:
        for _ in range(3):
            await _login(client, "admin", "wrong")

        assert (await _login(client, "admin", TEST_PASSWORD)).status_code == 303

        async with get_session_factory()() as session:
            user = await session.scalar(select(User).where(User.username == "admin"))
            assert user
            assert user.failed_login_count == 0
            assert user.locked_until is None
            assert user.last_login_at is not None


class TestSessionCookie:
    async def test_cookie_flags(self, auth_client: httpx.AsyncClient) -> None:
        cookie = auth_client.cookies.jar._cookies
        assert "netops_session" in auth_client.cookies

        response = await auth_client.get("/")
        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie:
            assert "httponly" in set_cookie.lower()
            assert "samesite=strict" in set_cookie.lower()
        assert cookie is not None

    async def test_session_identifier_is_replaced_on_login(self, client: httpx.AsyncClient) -> None:
        """Session fixation: whatever session the client arrived with must be
        discarded, not adopted, when authentication succeeds."""
        await client.get("/login")
        before = client.cookies.get("netops_session")

        await _login(client, "admin", TEST_PASSWORD)
        after = client.cookies.get("netops_session")

        assert after is not None
        assert after != before

    async def test_session_for_a_deleted_user_is_rejected(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        async with get_session_factory()() as session:
            user = await session.scalar(select(User).where(User.username == "admin"))
            assert user
            await session.delete(user)
            await session.commit()

        response = await auth_client.get("/")
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")


class TestForcedPasswordChange:
    async def _force(self) -> None:
        async with get_session_factory()() as session:
            user = await session.scalar(select(User).where(User.username == "admin"))
            assert user
            user.must_change_password = True
            await session.commit()

    async def test_login_lands_on_the_password_form(self, client: httpx.AsyncClient) -> None:
        await self._force()
        response = await _login(client, "admin", TEST_PASSWORD)
        assert response.status_code == 303
        assert response.headers["location"] == "/account/password"

    async def test_other_pages_redirect_until_the_password_is_changed(
        self, client: httpx.AsyncClient
    ) -> None:
        """The bootstrap password was printed to container logs. Allowing normal
        use before rotation would make that exposure permanent."""
        await self._force()
        await _login(client, "admin", TEST_PASSWORD)

        for path in ("/", "/settings"):
            response = await client.get(path)
            assert response.status_code == 303, path
            assert response.headers["location"] == "/account/password"

    async def test_changing_the_password_clears_the_requirement(
        self, client: httpx.AsyncClient
    ) -> None:
        await self._force()
        await _login(client, "admin", TEST_PASSWORD)

        token = await csrf_token(client, "/account/password")
        response = await client.post(
            "/account/password",
            data={
                "current_password": TEST_PASSWORD,
                "new_password": "a-considerably-longer-passphrase",
                "confirm_password": "a-considerably-longer-passphrase",
                "csrf_token": token,
            },
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/"
        assert (await client.get("/")).status_code == 200


class TestPasswordChangeValidation:
    async def _post(self, client: httpx.AsyncClient, **overrides: str) -> httpx.Response:
        token = await csrf_token(client, "/account/password")
        data = {
            "current_password": TEST_PASSWORD,
            "new_password": "a-considerably-longer-passphrase",
            "confirm_password": "a-considerably-longer-passphrase",
            "csrf_token": token,
        }
        data.update(overrides)
        return await client.post("/account/password", data=data)

    async def test_requires_the_current_password(self, auth_client: httpx.AsyncClient) -> None:
        """An authenticated session is not enough — this is what stops someone
        walking up to an unlocked screen from taking the account."""
        response = await self._post(auth_client, current_password="not-it")
        assert response.status_code == 400
        assert "Current password is incorrect" in response.text

    async def test_rejects_mismatched_confirmation(self, auth_client: httpx.AsyncClient) -> None:
        response = await self._post(auth_client, confirm_password="something-else-entirely")
        assert response.status_code == 400
        assert "do not match" in response.text

    async def test_rejects_a_short_password(self, auth_client: httpx.AsyncClient) -> None:
        response = await self._post(auth_client, new_password="short", confirm_password="short")
        assert response.status_code == 400
        assert "at least 12 characters" in response.text

    async def test_rejects_reusing_the_current_password(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        response = await self._post(
            auth_client, new_password=TEST_PASSWORD, confirm_password=TEST_PASSWORD
        )
        assert response.status_code == 400
        assert "different from the current" in response.text

    async def test_new_password_actually_works_afterwards(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        new = "an-entirely-different-passphrase"
        assert (
            await self._post(auth_client, new_password=new, confirm_password=new)
        ).status_code == 303

        token = await csrf_token(auth_client, "/settings")
        await auth_client.post("/logout", data={"csrf_token": token})

        assert (await _login(auth_client, "admin", new)).status_code == 303


class TestOpenRedirect:
    @pytest.mark.parametrize(
        "target",
        ["//evil.example.com", "https://evil.example.com", "http://evil.example.com/x"],
    )
    async def test_next_parameter_cannot_leave_the_origin(
        self, client: httpx.AsyncClient, target: str
    ) -> None:
        """A protocol-relative URL is absolute to a browser, so checking for a
        leading slash alone would still hand a phisher an open redirect."""
        token = await csrf_token(client, "/login")
        response = await client.post(
            "/login",
            data={
                "username": "admin",
                "password": TEST_PASSWORD,
                "next": target,
                "csrf_token": token,
            },
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/"

    async def test_a_same_origin_path_is_preserved(self, client: httpx.AsyncClient) -> None:
        token = await csrf_token(client, "/login")
        response = await client.post(
            "/login",
            data={
                "username": "admin",
                "password": TEST_PASSWORD,
                "next": "/settings",
                "csrf_token": token,
            },
        )
        assert response.headers["location"] == "/settings"
