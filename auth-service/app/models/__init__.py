"""Database models package.

All SQLAlchemy ORM models are imported here so they can be
discovered by Alembic for migration autogenerate and by
SQLAlchemy for relationship resolution.

Import order matters: models that are referenced by foreign keys
must be defined before the models that reference them.
"""

from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.association import UserRole, RolePermission
from app.models.session import Session
from app.models.refresh_token import RefreshToken
from app.models.audit_log import AuditLog

__all__ = [
    "User",
    "Role",
    "Permission",
    "UserRole",
    "RolePermission",
    "Session",
    "RefreshToken",
    "AuditLog",
]
