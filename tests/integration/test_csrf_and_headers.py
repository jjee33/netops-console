"""CSRF enforcement and security response headers.

CSRF is middleware rather than a per-route dependency, so these tests are
written to catch the failure that design prevents: a state-changing route that
someone adds later and forgets to protect.
"""

from __future__ import annotations

import httpx
import pytest
from tests.conftest import TEST_PASSWORD, csrf_token

from app.core.middleware import CONTENT_SECURITY_POLICY

STATE_CHANGING_PATHS = ["/logout", "/settings", "/account/password", "/login"]


class TestCsrfEnforcement:
    @pytest.mark.parametrize("path", STATE_CHANGING_PATHS)
    async def test_post_without_a_token_is_rejected(
        self, auth_client: httpx.AsyncClient, path: str
    ) -> None:
        response = await auth_client.post(path, data={})
        assert response.status_code == 403, f"{path} accepted a POST with no CSRF token"
        assert "CSRF" in response.text

    @pytest.mark.parametrize("path", STATE_CHANGING_PATHS)
    async def test_post_with_a_wrong_token_is_rejected(
        self, auth_client: httpx.AsyncClient, path: str
    ) -> None:
        response = await auth_client.post(path, data={"csrf_token": "not-the-right-token"})
        assert response.status_code == 403, path

    async def test_a_token_from_a_different_session_is_rejected(
        self, client: httpx.AsyncClient, seeded: object
    ) -> None:
        """Synchronizer, not double-submit: the expected value lives in the
        signed session, so a token lifted from elsewhere is worthless."""
        import httpx as _httpx

        from app.main import create_app

        stolen_transport = _httpx.ASGITransport(app=create_app())
        async with _httpx.AsyncClient(
            transport=stolen_transport, base_url="http://testserver"
        ) as other:
            stolen = await csrf_token(other, "/login")

        token = await csrf_token(client, "/login")
        assert stolen != token

        response = await client.post(
            "/login",
            data={
                "username": "admin",
                "password": TEST_PASSWORD,
                "next": "/",
                "csrf_token": stolen,
            },
        )
        assert response.status_code == 403

    async def test_the_header_form_of_the_token_is_accepted(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """HTMX sends the token as a header via hx-headers; forms send a field.
        Both must reach the same check."""
        token = await csrf_token(auth_client, "/settings")
        response = await auth_client.post(
            "/settings",
            data={
                "allowed_cidrs": "10.0.0.0/16",
                "max_scan_hosts": "1024",
                "max_concurrent_scans": "1",
                "max_concurrent_executions": "4",
                "retention_days": "90",
            },
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 200
        assert "Settings saved" in response.text

    async def test_the_request_body_survives_csrf_inspection(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """The middleware reads the body to find the token and must replay it.

        If it does not, the route sees an empty body and every form POST fails
        validation with 422 while the middleware appears to work — which is
        exactly what BaseHTTPMiddleware does here.
        """
        token = await csrf_token(auth_client, "/settings")
        response = await auth_client.post(
            "/settings",
            data={
                "allowed_cidrs": "192.168.50.0/24",
                "max_scan_hosts": "256",
                "max_concurrent_scans": "2",
                "max_concurrent_executions": "3",
                "retention_days": "30",
                "csrf_token": token,
            },
        )
        assert response.status_code == 200, response.text
        assert "192.168.50.0/24" in response.text
        assert "256" in response.text

    @pytest.mark.parametrize("path", ["/", "/login", "/settings", "/account/password"])
    async def test_get_requests_never_need_a_token(
        self, auth_client: httpx.AsyncClient, path: str
    ) -> None:
        # Asserting "not 403" rather than "200": an authenticated client is
        # redirected away from /login, which is correct and not the subject here.
        assert (await auth_client.get(path)).status_code != 403

    async def test_healthz_is_exempt_and_still_safe(self, client: httpx.AsyncClient) -> None:
        assert (await client.get("/healthz")).status_code == 200


class TestSecurityHeaders:
    @pytest.mark.parametrize("path", ["/login", "/healthz"])
    async def test_headers_present_on_every_response(
        self, client: httpx.AsyncClient, path: str
    ) -> None:
        response = await client.get(path)
        assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"

    def test_policy_forbids_inline_and_remote_script(self) -> None:
        """The CSP is defence in depth for rendering command output from
        untrusted hosts. 'unsafe-inline' would remove the entire benefit."""
        assert "unsafe-inline" not in CONTENT_SECURITY_POLICY
        assert "unsafe-eval" not in CONTENT_SECURITY_POLICY
        assert "script-src 'self'" in CONTENT_SECURITY_POLICY
        assert "frame-ancestors 'none'" in CONTENT_SECURITY_POLICY
        assert "object-src 'none'" in CONTENT_SECURITY_POLICY

    async def test_hsts_is_absent_over_plain_http(self, client: httpx.AsyncClient) -> None:
        """Sending HSTS over http pins a hostname to https for anyone who ever
        loaded it, including colleagues on a lab hostname."""
        response = await client.get("/login")
        assert "strict-transport-security" not in response.headers

    async def test_hsts_is_set_when_the_proxy_reports_https(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/login", headers={"X-Forwarded-Proto": "https"})
        assert "max-age=31536000" in response.headers["strict-transport-security"]


class TestOutputEscaping:
    async def test_error_text_is_escaped_in_the_settings_page(
        self, auth_client: httpx.AsyncClient
    ) -> None:
        """Validation errors echo user input. Autoescaping must hold there —
        this is the same path that will render command output in Phase 2."""
        token = await csrf_token(auth_client, "/settings")
        payload = "<script>alert(1)</script>"
        response = await auth_client.post(
            "/settings",
            data={
                "allowed_cidrs": payload,
                "max_scan_hosts": "1024",
                "max_concurrent_scans": "1",
                "max_concurrent_executions": "4",
                "retention_days": "90",
                "csrf_token": token,
            },
        )
        assert response.status_code == 400
        assert payload not in response.text
        assert "&lt;script&gt;" in response.text
