"""Application settings, driven by environment variables.

Anything security-relevant is resolved once here so there is a single place to
audit. Secrets are read from files rather than taken directly from environment
variables: an env var is visible to anything that can run `docker inspect`.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NETOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- Binding ------------------------------------------------------------
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    forwarded_allow_ips: str = "127.0.0.1"
    workers: int = 1

    # -- Storage and keys ---------------------------------------------------
    db_path: Path = Path("/data/netops.db")
    secret_key_file: Path = Path("/data/secrets/secret_key")
    crypto_key_file: Path = Path("/data/secrets/crypto_key")

    # -- Bootstrap ----------------------------------------------------------
    admin_username: str = "admin"
    admin_password: str | None = None

    # -- Defaults seeded into the settings table on first run ---------------
    allowed_cidrs: list[str] = Field(
        default_factory=lambda: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    )
    max_scan_hosts: int = 1024
    max_concurrent_scans: int = 1
    max_concurrent_executions: int = 4
    retention_days: int = 90

    log_level: str = "info"
    environment: str = "production"

    @field_validator("allowed_cidrs", mode="before")
    @classmethod
    def _split_cidrs(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("allowed_cidrs")
    @classmethod
    def _validate_cidrs(cls, value: list[str]) -> list[str]:
        for cidr in value:
            # Raises ValueError on anything that is not a valid IPv4 network.
            # Host bits set is a configuration mistake worth surfacing loudly
            # rather than silently normalising away.
            ipaddress.IPv4Network(cidr, strict=True)
        return value

    @field_validator("workers")
    @classmethod
    def _single_worker_only(cls, value: int) -> int:
        # Concurrency caps, scan limits, and the execution semaphore are
        # in-process. A second worker gets its own copy of all of them and
        # silently multiplies every limit. This is a safety property.
        if value != 1:
            raise ValueError(
                "NETOPS_WORKERS must be 1 — concurrency limits are enforced "
                "in-process and additional workers void them silently."
            )
        return value

    @property
    def database_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"

    def read_secret_key(self) -> str:
        return self._read_key(self.secret_key_file, "session-signing")

    def read_crypto_key(self) -> bytes:
        return self._read_key(self.crypto_key_file, "credential-encryption").encode()

    @staticmethod
    def _read_key(path: Path, kind: str) -> str:
        try:
            key = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"{kind} key not found at {path}. The container entrypoint "
                f"generates one on first start; if you are running outside the "
                f"container, create it or point NETOPS_*_KEY_FILE at yours."
            ) from exc
        if not key:
            raise RuntimeError(f"{kind} key at {path} is empty — refusing to start.")
        return key


@lru_cache
def get_settings() -> Settings:
    return Settings()
