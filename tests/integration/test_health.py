"""The only unauthenticated endpoint. It must disclose nothing."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from app.main import create_app


@pytest.fixture
def client(env: Path) -> httpx.AsyncClient:
    app = create_app()
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


async def test_healthz_returns_200_and_an_empty_body(client: httpx.AsyncClient) -> None:
    async with client:
        response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.content == b""


async def test_healthz_does_not_leak_version_or_build_info(client: httpx.AsyncClient) -> None:
    """A liveness probe is a free fingerprinting endpoint if it echoes a version."""
    from app import __version__

    async with client:
        response = await client.get("/healthz")

    body = response.content.decode()
    assert __version__ not in body
    combined = " ".join(f"{k}: {v}" for k, v in response.headers.items())
    assert __version__ not in combined
    assert "netops" not in combined.lower()


async def test_healthz_accepts_head(client: httpx.AsyncClient) -> None:
    """Uptime monitors commonly default to HEAD; a 405 there reads as an outage."""
    async with client:
        response = await client.head("/healthz")
    assert response.status_code == 200


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_api_documentation_endpoints_are_disabled(
    client: httpx.AsyncClient, path: str
) -> None:
    """This is an admin panel, not a public API. Schema disclosure is free recon."""
    async with client:
        assert (await client.get(path)).status_code == 404
