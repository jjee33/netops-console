"""Runtime assertions executed inside a running container by CI.

Piped in over stdin (`docker exec -i ... python - < this_file`) so it can be a
real, readable file instead of a quoted one-liner wedged into YAML.

Checks the things that are configured in one place and silently ineffective in
another: pragmas that are set per connection, and a backup that has to be
consistent while the application is writing.
"""

from __future__ import annotations

import sqlite3
import sys

DB = "/data/netops.db"
failures: list[str] = []


def check(label: str, actual: object, expected: object) -> None:
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r} (expected {expected!r})")
    if not ok:
        failures.append(label)


print("database file:")
conn = sqlite3.connect(DB)
try:
    # journal_mode is persistent in the file itself, so this is a real check of
    # what the application did to the database, not of this connection.
    check("journal_mode", conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
    check("integrity_check", conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    check("user table exists", "user" in tables, True)
    check("alembic stamped", "alembic_version" in tables, True)

    users = conn.execute("SELECT count(*) FROM user").fetchone()[0]
    check("exactly one bootstrapped account", users, 1)

    must_change = conn.execute("SELECT must_change_password FROM user").fetchone()[0]
    check("generated password must be rotated", bool(must_change), True)
finally:
    conn.close()

print("\nbackup:")
backup_path = "/tmp/ci-backup.db"
src = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
try:
    # VACUUM INTO, not a file copy: under WAL a copied .db can be a torn state.
    src.execute("VACUUM INTO ?", (backup_path,))
finally:
    src.close()

backup = sqlite3.connect(backup_path)
try:
    check("backup integrity", backup.execute("PRAGMA integrity_check").fetchone()[0], "ok")
    check("backup has the user row", backup.execute("SELECT count(*) FROM user").fetchone()[0], 1)
finally:
    backup.close()

if failures:
    print(f"\n{len(failures)} check(s) failed: {', '.join(failures)}", file=sys.stderr)
    sys.exit(1)

print("\nall runtime checks passed")
