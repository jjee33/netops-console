"""Operational commands invoked by the container entrypoint.

Kept deliberately small. Anything an operator needs to do outside the UI belongs
here so it is version-controlled and testable, not in shell snippets in docs.
"""

from __future__ import annotations

import argparse
import asyncio
import sqlite3
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import dispose_engine, get_session_factory
from app.core.security import generate_password, hash_password
from app.models import User


async def _bootstrap_admin() -> int:
    """Create the initial account if, and only if, no accounts exist.

    Idempotent: this runs on every container start. A fixed default password on
    a publicly distributed tool that holds SSH keys would be a vulnerability, so
    the password is random and printed exactly once.
    """
    settings = get_settings()

    async with get_session_factory()() as session:
        existing = await session.scalar(select(User.id).limit(1))
        if existing is not None:
            print("[bootstrap] an account already exists; leaving it alone")
            return 0

        supplied = settings.admin_password
        password = supplied or generate_password()

        user = User(
            username=settings.admin_username,
            password_hash=hash_password(password),
            is_active=True,
            # Force a change even when supplied via env: an environment
            # variable is readable by anything that can run `docker inspect`.
            must_change_password=True,
        )
        session.add(user)
        await session.commit()

    if supplied:
        print(
            f"\n[bootstrap] Initial admin account '{settings.admin_username}' created "
            f"with the password from NETOPS_ADMIN_PASSWORD.\n"
            f"            You will be required to change it at first login.\n"
        )
    else:
        print(
            "\n"
            "  ┌──────────────────────────────────────────────────────────────────────┐\n"
            "  │  Initial admin account created. This is shown ONCE.                  │\n"
            "  └──────────────────────────────────────────────────────────────────────┘\n"
            f"\n      username:  {settings.admin_username}\n"
            f"      password:  {password}\n"
            "\n"
            "      You must change this at first login. If you lose it before then,\n"
            "      run:  docker compose exec app python -m app.cli reset-password\n"
        )
    return 0


async def _reset_password(username: str) -> int:
    settings = get_settings()
    target = username or settings.admin_username

    async with get_session_factory()() as session:
        user = await session.scalar(select(User).where(User.username == target))
        if user is None:
            print(f"[reset-password] no such user: {target}", file=sys.stderr)
            return 1

        password = generate_password()
        user.password_hash = hash_password(password)
        user.must_change_password = True
        user.failed_login_count = 0
        user.locked_until = None
        await session.commit()

    print(f"\n      username:  {target}\n      password:  {password}\n")
    print("      Change it at next login.\n")
    return 0


def _backup(destination: str) -> int:
    """Take a consistent copy of the database.

    ``VACUUM INTO`` is used rather than a file copy: under WAL, copying the .db
    file while the application is running captures a torn state that may not
    open. This is safe to run against a live instance.
    """
    settings = get_settings()
    dest = Path(destination)

    if dest.exists():
        print(f"[backup] refusing to overwrite existing file: {dest}", file=sys.stderr)
        return 1

    with sqlite3.connect(f"file:{settings.db_path}?mode=ro", uri=True) as conn:
        conn.execute("VACUUM INTO ?", (str(dest),))

    print(f"[backup] wrote {dest} ({dest.stat().st_size} bytes)")
    print(
        "[backup] This does NOT include the credential-encryption key. Back up\n"
        f"         {settings.crypto_key_file} separately — storing it alongside\n"
        "         the database defeats the encryption."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli", description="NetOps Console operations")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("bootstrap-admin", help="create the initial account if none exists")

    reset = sub.add_parser("reset-password", help="set a new random password for an account")
    reset.add_argument("--username", default="", help="defaults to NETOPS_ADMIN_USERNAME")

    backup = sub.add_parser("backup", help="write a consistent database copy")
    backup.add_argument("destination", nargs="?", default="/data/backup.db")

    args = parser.parse_args(argv)

    try:
        if args.command == "bootstrap-admin":
            return asyncio.run(_run(_bootstrap_admin()))
        if args.command == "reset-password":
            return asyncio.run(_run(_reset_password(args.username)))
        if args.command == "backup":
            return _backup(args.destination)
    except KeyboardInterrupt:  # pragma: no cover
        return 130

    parser.error(f"unknown command: {args.command}")
    return 2


async def _run(coro: Coroutine[Any, Any, int]) -> int:
    try:
        return await coro
    finally:
        await dispose_engine()


if __name__ == "__main__":
    raise SystemExit(main())
