from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_workers_must_be_one() -> None:
    """More than one worker silently voids every concurrency cap in the app.

    The caps are enforced with in-process state, so each worker gets its own
    copy. Failing loudly at startup is the only way an operator finds out.
    """
    with pytest.raises(ValidationError, match="must be 1"):
        Settings(workers=4)


def test_single_worker_accepted() -> None:
    assert Settings(workers=1).workers == 1


def test_allowed_cidrs_parsed_from_comma_separated_env() -> None:
    settings = Settings(allowed_cidrs="10.0.0.0/8, 192.168.1.0/24")  # type: ignore[arg-type]
    assert settings.allowed_cidrs == ["10.0.0.0/8", "192.168.1.0/24"]


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-cidr",
        "10.0.0.0/33",
        "192.168.1.5/24",  # host bits set — a config mistake worth surfacing
        "2001:db8::/32",  # IPv6 is out of scope for v0.1
    ],
)
def test_invalid_cidr_rejected(bad: str) -> None:
    with pytest.raises(ValidationError):
        Settings(allowed_cidrs=[bad])


def test_database_url_uses_async_driver() -> None:
    settings = Settings(db_path="/data/netops.db")  # type: ignore[arg-type]
    assert settings.database_url == "sqlite+aiosqlite:////data/netops.db"


def test_missing_key_file_raises_actionable_error(tmp_path) -> None:
    settings = Settings(secret_key_file=tmp_path / "nope")
    with pytest.raises(RuntimeError, match="not found"):
        settings.read_secret_key()


def test_empty_key_file_is_rejected(tmp_path) -> None:
    """An empty key file means a broken first start, not a valid empty secret."""
    path = tmp_path / "crypto_key"
    path.write_text("   \n")
    settings = Settings(crypto_key_file=path)
    with pytest.raises(RuntimeError, match="empty"):
        settings.read_crypto_key()
