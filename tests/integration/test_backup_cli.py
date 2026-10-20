"""The backup and verify-backup commands.

An untested backup is a guess. These cover what an operator relies on: a live
backup that verifies, a file that is damaged or foreign being rejected, a
schema newer than the running code being refused, and a key that does not
belong to the backup being caught before the original is gone.
"""

from __future__ import annotations

import base64
import os
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from app.cli import main
from app.core.crypto import reset_cipher
from app.core.db import get_session_factory
from app.modules.credentials import service as credentials_service

SECRET = "synthetic-backup-secret-7d1e"


async def _store_credential() -> None:
    async with get_session_factory()() as session:
        await credentials_service.create(
            session,
            name="Backup test",
            username="netops",
            auth_type="password",
            secret=SECRET,
            passphrase=None,
            description="",
        )


class TestBackupAndVerify:
    async def test_a_fresh_backup_verifies(
        self, seeded: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        destination = tmp_path / "backup.db"
        assert main(["backup", str(destination)]) == 0
        assert main(["verify-backup", str(destination)]) == 0

        out = capsys.readouterr().out
        assert "integrity_check: ok" in out
        assert "(matches this version)" in out
        assert "user" in out and "[verify] OK" in out

    async def test_backup_refuses_to_overwrite(self, seeded: Path, tmp_path: Path) -> None:
        destination = tmp_path / "backup.db"
        destination.write_text("my only backup")
        assert main(["backup", str(destination)]) == 1
        assert destination.read_text() == "my only backup"

    async def test_check_key_confirms_credentials_decrypt(
        self, seeded: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        await _store_credential()
        destination = tmp_path / "backup.db"
        main(["backup", str(destination)])

        assert main(["verify-backup", "--check-key", str(destination)]) == 0
        out = capsys.readouterr().out
        assert "1 of 1" in out
        assert SECRET not in out

    async def test_a_key_from_another_install_is_caught(
        self, seeded: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        await _store_credential()
        destination = tmp_path / "backup.db"
        main(["backup", str(destination)])

        # Simulate restoring with the wrong key file.
        key_file = Path(os.environ["NETOPS_CRYPTO_KEY_FILE"])
        key_file.write_text(base64.urlsafe_b64encode(os.urandom(32)).decode())
        reset_cipher()
        try:
            assert main(["verify-backup", "--check-key", str(destination)]) == 1
        finally:
            reset_cipher()

        captured = capsys.readouterr()
        assert "0 of 1" in captured.out
        assert "Backup test" in captured.out
        assert SECRET not in captured.out + captured.err

    async def test_verification_never_modifies_the_file(self, seeded: Path, tmp_path: Path) -> None:
        destination = tmp_path / "backup.db"
        main(["backup", str(destination)])
        before = destination.read_bytes()
        main(["verify-backup", "--check-key", str(destination)])
        assert destination.read_bytes() == before


class TestRejections:
    def test_missing_file(self, env: Path, tmp_path: Path) -> None:
        assert main(["verify-backup", str(tmp_path / "absent.db")]) == 1

    def test_damaged_file(
        self, env: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        damaged = tmp_path / "damaged.db"
        damaged.write_bytes(b"SQLite format 3\x00" + os.urandom(4096))
        assert main(["verify-backup", str(damaged)]) == 1

    def test_a_database_from_something_else(self, env: Path, tmp_path: Path) -> None:
        foreign = tmp_path / "foreign.db"
        with closing(sqlite3.connect(foreign)) as conn, conn:
            conn.execute("CREATE TABLE notes (body TEXT)")
        assert main(["verify-backup", str(foreign)]) == 1

    async def test_a_newer_schema_is_refused(
        self, seeded: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        destination = tmp_path / "backup.db"
        main(["backup", str(destination)])
        with closing(sqlite3.connect(destination)) as conn, conn:
            conn.execute("UPDATE alembic_version SET version_num = 'ffffffffffff'")

        assert main(["verify-backup", str(destination)]) == 1
        assert "NEWER than this version" in capsys.readouterr().out

    async def test_an_older_schema_verifies_and_says_it_will_upgrade(
        self, seeded: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        destination = tmp_path / "backup.db"
        main(["backup", str(destination)])
        with closing(sqlite3.connect(destination)) as conn, conn:
            conn.execute("UPDATE alembic_version SET version_num = '36c5a90d852f'")

        assert main(["verify-backup", str(destination)]) == 0
        assert "upgraded automatically on start" in capsys.readouterr().out
