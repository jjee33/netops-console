"""Upgrade and rollback with data in the database.

CI already checks that migrations apply to an empty database and reverse
cleanly. An empty database proves very little about an upgrade: the failure an
operator actually meets is existing rows that a migration mishandles. These
tests put representative rows in first.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from tests.conftest import run_alembic

PREVIOUS = "36c5a90d852f"
HISTORY_REVISION = "4cdd051ae46a"


def _alembic(db: Path, *arguments: str) -> None:
    result = run_alembic(*arguments, db_path=db)
    if result.returncode != 0:
        pytest.fail(f"alembic {' '.join(arguments)} failed:\n{result.stderr}")


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _seed_previous_schema(db: Path) -> None:
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO user (id, username, password_hash, is_active, must_change_password,"
            " failed_login_count) VALUES (1, 'admin', 'x', 1, 0, 0)"
        )
        conn.execute(
            "INSERT INTO device (id, ip_address, mac_address, status, is_deleted)"
            " VALUES (1, '10.0.0.5', 'aa:bb:cc:dd:ee:01', 'online', 0)"
        )
        conn.execute(
            "INSERT INTO discovery_run (id, subnet, user_id, status, devices_found, devices_new)"
            " VALUES (1, '10.0.0.0/24', 1, 'success', 1, 1)"
        )


class TestHistoryMigration:
    def test_upgrade_preserves_existing_rows(self, tmp_path: Path) -> None:
        db = tmp_path / "upgrade.db"
        _alembic(db, "upgrade", PREVIOUS)
        _seed_previous_schema(db)

        _alembic(db, "upgrade", "head")

        with sqlite3.connect(db) as conn:
            assert {"discovery_observation", "change_event"} <= _tables(conn)
            run = conn.execute("SELECT subnet, status, scanned_ports FROM discovery_run").fetchone()
            # NULL, not False: an old run's port coverage is unknown, and
            # reading it as "did not scan ports" would be a guess.
            assert run == ("10.0.0.0/24", "success", None)
            assert conn.execute("SELECT ip_address FROM device").fetchone() == ("10.0.0.5",)
            assert conn.execute("SELECT count(*) FROM discovery_observation").fetchone() == (0,)

    def test_rollback_drops_only_the_new_history(self, tmp_path: Path) -> None:
        db = tmp_path / "rollback.db"
        _alembic(db, "upgrade", PREVIOUS)
        _seed_previous_schema(db)
        _alembic(db, "upgrade", "head")

        with sqlite3.connect(db) as conn:
            conn.execute(
                "INSERT INTO discovery_observation (run_id, device_id, present, ip_address,"
                " observed_at) VALUES (1, 1, 1, '10.0.0.5', '2026-10-01 00:00:00')"
            )
            conn.execute(
                "INSERT INTO change_event (created_at, kind, device_id, detail)"
                " VALUES ('2026-10-01 00:00:00', 'device_edited', 1, 'name set')"
            )

        _alembic(db, "downgrade", PREVIOUS)

        with sqlite3.connect(db) as conn:
            tables = _tables(conn)
            assert "discovery_observation" not in tables
            assert "change_event" not in tables
            columns = {row[1] for row in conn.execute("PRAGMA table_info(discovery_run)")}
            assert "scanned_ports" not in columns
            # Everything that existed before the upgrade is still there.
            assert conn.execute("SELECT count(*) FROM discovery_run").fetchone() == (1,)
            assert conn.execute("SELECT count(*) FROM device").fetchone() == (1,)
            assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

        # And the upgrade can be applied again after a rollback.
        _alembic(db, "upgrade", "head")

    def test_constraint_rejects_an_unknown_change_kind(self, tmp_path: Path) -> None:
        db = tmp_path / "constraint.db"
        _alembic(db, "upgrade", "head")
        with sqlite3.connect(db) as conn, pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO change_event (created_at, kind) VALUES ('2026-10-01', 'free_text')"
            )
