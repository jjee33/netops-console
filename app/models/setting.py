"""Runtime configuration stored in the database.

Distinct from ``app/core/config.py``, which holds deployment-time settings that
come from the environment (paths, bind address, keys). Anything an operator can
change from the UI lives here instead, so a change survives a container restart
without editing compose files.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Setting(Base):
    __tablename__ = "setting"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)

    # JSON rather than a column per setting: these are read as a block at
    # startup and edited as a block in the UI, and a new setting should not
    # require a migration.
    value: Mapped[Any] = mapped_column(JSON, nullable=False)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Setting {self.key}={self.value!r}>"
