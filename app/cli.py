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
from contextlib import closing
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

    # closing(): a sqlite3 connection's own context manager commits but never
    # closes, which leaked the handle on every backup.
    with closing(sqlite3.connect(f"file:{settings.db_path}?mode=ro", uri=True)) as conn:
        conn.execute("VACUUM INTO ?", (str(dest),))

    print(f"[backup] wrote {dest} ({dest.stat().st_size} bytes)")
    print(
        "[backup] This does NOT include the credential-encryption key. Back up\n"
        f"         {settings.crypto_key_file} separately — storing it alongside\n"
        "         the database defeats the encryption."
    )
    return 0


# Tables counted in a verification report. Missing ones are skipped, so an
# older backup that predates a table still verifies.
_REPORTED_TABLES = (
    "user",
    "device",
    "discovery_run",
    "discovery_observation",
    "diagnostic_result",
    "action_execution",
    "change_event",
    "credential",
)

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


def _code_head_revision() -> str | None:
    """The newest migration this version of the code ships."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    if not ALEMBIC_INI.exists():  # pragma: no cover - always present in the image
        return None
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "migrations"))
    return ScriptDirectory.from_config(config).get_current_head()


def _known_revisions() -> set[str]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "migrations"))
    return {script.revision for script in ScriptDirectory.from_config(config).walk_revisions()}


def _verify_backup(source: str, *, check_key: bool) -> int:
    """Check that a backup file is usable before it is needed.

    Opens the file read-only and never modifies it. Reports integrity, foreign
    key consistency, the schema revision relative to this version of the code,
    and row counts. With ``check_key``, also confirms every stored credential
    decrypts with the key this instance is configured with — the step a restore
    drill otherwise needs a real SSH target for. No secret is ever printed.

    Exit status is non-zero when the file is damaged, is not a NetOps database,
    or carries a schema newer than this code understands.
    """
    path = Path(source)
    if not path.is_file():
        print(f"[verify] no such file: {path}", file=sys.stderr)
        return 1

    problems: list[str] = []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        print(f"[verify] cannot open {path}: {exc}", file=sys.stderr)
        return 1

    with closing(conn):
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        except sqlite3.DatabaseError as exc:
            print(f"[verify] {path} is not a readable SQLite database: {exc}", file=sys.stderr)
            return 1
        print(f"[verify] integrity_check: {integrity}")
        if integrity != "ok":
            problems.append("integrity check failed")

        orphans = conn.execute("PRAGMA foreign_key_check").fetchall()
        print(f"[verify] foreign_key_check: {len(orphans)} problem(s)")
        if orphans:
            problems.append("foreign key inconsistencies")

        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "alembic_version" not in tables:
            print(
                "[verify] no alembic_version table: not a NetOps Console database", file=sys.stderr
            )
            return 1

        revision_row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        revision = revision_row[0] if revision_row else None
        head = _code_head_revision()
        if revision == head:
            print(f"[verify] schema revision: {revision} (matches this version)")
        elif revision in _known_revisions():
            print(
                f"[verify] schema revision: {revision} (older than this version's {head}; "
                "it will be upgraded automatically on start)"
            )
        else:
            print(
                f"[verify] schema revision: {revision} is NEWER than this version "
                f"({head}) or unknown to it. Restore it with the image that wrote it."
            )
            problems.append("schema newer than this version")

        for table in _REPORTED_TABLES:
            if table in tables:
                # Table names come from the fixed tuple above, never from input.
                count = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]  # noqa: S608
                print(f"[verify]   {table:<22} {count:>8} row(s)")

        if check_key and "credential" in tables:
            from app.core.crypto import DecryptionError, decrypt

            rows = conn.execute(
                "SELECT name, secret_ciphertext, passphrase_ciphertext FROM credential"
            ).fetchall()
            failed = []
            for name, secret, passphrase in rows:
                try:
                    decrypt(secret)
                    if passphrase:
                        decrypt(passphrase)
                except DecryptionError:
                    failed.append(name)
            print(
                f"[verify] credentials decrypting with the configured key: "
                f"{len(rows) - len(failed)} of {len(rows)}"
            )
            if failed:
                print(
                    "[verify] these do not decrypt — the key does not belong to this backup: "
                    + ", ".join(failed)
                )
                problems.append("credentials do not decrypt with the configured key")

    if problems:
        print(f"[verify] FAILED: {'; '.join(problems)}", file=sys.stderr)
        return 1
    print("[verify] OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli", description="NetOps Console operations")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("bootstrap-admin", help="create the initial account if none exists")

    reset = sub.add_parser("reset-password", help="set a new random password for an account")
    reset.add_argument("--username", default="", help="defaults to NETOPS_ADMIN_USERNAME")

    backup = sub.add_parser("backup", help="write a consistent database copy")
    backup.add_argument("destination", nargs="?", default="/data/backup.db")

    verify = sub.add_parser(
        "verify-backup", help="check a backup file read-only before you need it"
    )
    verify.add_argument("source", nargs="?", default="/data/backup.db")
    verify.add_argument(
        "--check-key",
        action="store_true",
        help="also confirm stored credentials decrypt with the configured crypto_key",
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "bootstrap-admin":
            return asyncio.run(_run(_bootstrap_admin()))
        if args.command == "reset-password":
            return asyncio.run(_run(_reset_password(args.username)))
        if args.command == "backup":
            return _backup(args.destination)
        if args.command == "verify-backup":
            return _verify_backup(args.source, check_key=args.check_key)
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
