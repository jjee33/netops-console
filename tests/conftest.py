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
