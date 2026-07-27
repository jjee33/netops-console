"""Shared fixtures.

Every test gets its own SQLite file and its own key files. Settings are cached
with ``lru_cache``, so the cache must be cleared after the environment changes
or tests silently share the first test's configuration.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from app.core.config import get_settings

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_key(path: Path) -> None:
    path.write_text(base64.urlsafe_b64encode(os.urandom(32)).decode(), encoding="utf-8")
    path.chmod(0o600)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the application at an isolated database and freshly generated keys."""
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    secret_key = secrets_dir / "secret_key"
    crypto_key = secrets_dir / "crypto_key"
    _write_key(secret_key)
    _write_key(crypto_key)

    monkeypatch.setenv("NETOPS_DB_PATH", str(tmp_path / "netops.db"))
    monkeypatch.setenv("NETOPS_SECRET_KEY_FILE", str(secret_key))
    monkeypatch.setenv("NETOPS_CRYPTO_KEY_FILE", str(crypto_key))
    monkeypatch.setenv("NETOPS_ENVIRONMENT", "test")

    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def migrated(env: Path) -> AsyncIterator[Path]:
    """An isolated database with the schema applied by Alembic.

    Alembic runs in a subprocess rather than in-process: it drives its own event
    loop, and nesting that inside pytest-asyncio's loop deadlocks.
    """
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env={**os.environ},
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade failed:\n{result.stdout}\n{result.stderr}")

    from app.core.db import dispose_engine

    yield env
    await dispose_engine()


TEST_PASSWORD = "bootstrap-password-1234"


@pytest.fixture(autouse=True)
def _reset_login_throttle() -> Iterator[None]:
    """Clear the per-IP login throttle around every test.

    The throttle is deliberately process-global in production — there is one
    worker, so one shared counter is the correct design. In a test session that
    means failed-login tests accumulate against 127.0.0.1 and eventually rate
    limit every later test, which looks like a bug in whatever ran last.
    """
    from app.modules.auth.throttle import login_throttle

    login_throttle._buckets.clear()
    yield
    login_throttle._buckets.clear()


@pytest_asyncio.fixture
async def seeded(migrated: Path) -> AsyncIterator[Path]:
    """A migrated database with one admin account, password :data:`TEST_PASSWORD`.

    ``must_change_password`` is cleared here — the forced-rotation path has its
    own tests, and leaving it set would send every other test to the password
    form instead of the page under test.
    """
    from sqlalchemy import select

    from app.core.db import get_session_factory
    from app.core.security import hash_password
    from app.models import User

    async with get_session_factory()() as session:
        session.add(
            User(
                username="admin",
                password_hash=hash_password(TEST_PASSWORD),
                is_active=True,
                must_change_password=False,
            )
        )
        await session.commit()
        assert await session.scalar(select(User.id))

    yield migrated


@pytest_asyncio.fixture
async def client(seeded: Path) -> AsyncIterator[httpx.AsyncClient]:
    """An unauthenticated client against a freshly built app."""
    import httpx

    from app.main import create_app

    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as instance:
        yield instance


@pytest_asyncio.fixture
async def auth_client(client: httpx.AsyncClient) -> httpx.AsyncClient:
    """A client that has completed login."""
    token = await csrf_token(client, "/login")
    response = await client.post(
        "/login",
        data={"username": "admin", "password": TEST_PASSWORD, "next": "/", "csrf_token": token},
    )
    assert response.status_code == 303, response.text
    return client


async def csrf_token(client: httpx.AsyncClient, path: str) -> str:
    """Fetch a page and extract its CSRF token."""
    import re

    response = await client.get(path)
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, f"no CSRF token in {path} (status {response.status_code})"
    return match.group(1)


if TYPE_CHECKING:  # pragma: no cover
    import httpx
