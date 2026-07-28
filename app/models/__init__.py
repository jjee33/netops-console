"""SQLAlchemy models.

Every model must be imported here so Alembic's autogenerate sees it in
``Base.metadata``. A model that is defined but not imported produces an empty
migration and a schema that silently drifts from the code.
"""

from app.models.action import ActionDefinition, ActionExecution
from app.models.device import Device, DevicePort
from app.models.diagnostic import DiagnosticResult
from app.models.discovery import DiscoveryRun
from app.models.setting import Setting
from app.models.user import User

__all__ = [
    "ActionDefinition",
    "ActionExecution",
    "Device",
    "DevicePort",
    "DiagnosticResult",
    "DiscoveryRun",
    "Setting",
    "User",
]
