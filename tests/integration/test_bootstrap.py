"""First-run bootstrap.

The entrypoint runs this on every container start, so idempotency is not a nice
property — a second run that reset the admin password would lock the operator
out on every restart.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import select

from app.core.db import get_session_factory
from app.models import User

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "app.cli", *args],
        cwd=REPO_ROOT,
        env={**os.environ},
        capture_output=True,
        text=True,
        check=False,
    )


async def test_bootstrap_creates_one_admin_with_a_random_password(migrated: Path) -> None:
    result = _run_cli("bootstrap-admin")
    assert result.returncode == 0, result.stderr
    assert "Initial admin account created" in result.stdout

    async with get_session_factory()() as session:
        users = (await session.scalars(select(User))).all()

    assert len(users) == 1
    user = users[0]
    assert user.username == "admin"
    assert user.password_hash.startswith("$argon2id$")
    assert user.must_change_password is True, "a generated password must be rotated"


async def test_bootstrap_is_idempotent(migrated: Path) -> None:
    assert _run_cli("bootstrap-admin").returncode == 0

    async with get_session_factory()() as session:
        original = (await session.scalars(select(User))).one()
        original_hash = original.password_hash

    second = _run_cli("bootstrap-admin")
    assert second.returncode == 0
    assert "already exists" in second.stdout

    async with get_session_factory()() as session:
        users = (await session.scalars(select(User))).all()

    assert len(users) == 1
    assert users[0].password_hash == original_hash, "restart must not rotate the password"


async def test_generated_password_is_not_a_fixed_default(migrated: Path, tmp_path: Path) -> None:
    """Two independent installs must not share a password.

    A predictable default on a publicly distributed tool that stores SSH keys is
    a vulnerability, not a convenience.
    """
    first = _run_cli("bootstrap-admin")
    assert first.returncode == 0
    first_password = _extract_password(first.stdout)

    second_db = tmp_path / "second.db"
    env = {**os.environ, "NETOPS_DB_PATH": str(second_db)}
    assert (
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
        ).returncode
        == 0
    )
    second = subprocess.run(
        [sys.executable, "-m", "app.cli", "bootstrap-admin"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert second.returncode == 0

    assert first_password != _extract_password(second.stdout)


def _extract_password(output: str) -> str:
    for line in output.splitlines():
        if "password:" in line:
            return line.split("password:", 1)[1].strip()
    raise AssertionError(f"no password in bootstrap output:\n{output}")
