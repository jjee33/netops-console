"""SQLAlchemy models.

Every model must be imported here so Alembic's autogenerate sees it in
``Base.metadata``. A model that is defined but not imported produces an empty
migration and a schema that silently drifts from the code.
"""

from app.models.setting import Setting
from app.models.user import User

__all__ = ["Setting", "User"]
