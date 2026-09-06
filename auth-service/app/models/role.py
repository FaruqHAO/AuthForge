"""Role model.

Represents a named role that can be assigned to users.
Roles aggregate permissions — a user's effective permissions are
the union of all permissions from all their assigned roles.

Example roles: ADMIN, MANAGER, SUPPORT, USER

Design decisions:
- `is_default` flag: new users can be auto-assigned default roles
- `name` is unique and uppercase-normalized for consistency
- Hard delete is acceptable for roles (they're configuration, not user data)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(Base):
    """Role entity for RBAC."""

    __tablename__ = "roles"

    # ── Primary Key ──────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ── Identity ─────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        comment="Role name (e.g., ADMIN, USER)",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable description of the role",
    )
    is_default: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="false",
        comment="If true, assigned to new users during registration",
    )

    # ── Timestamps ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
        server_default="now()",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
        server_default="now()",
    )

    # ── Relationships ────────────────────────────────────────────────────
    user_roles: Mapped[list[UserRole]] = relationship(
        "UserRole",
        back_populates="role",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    role_permissions: Mapped[list[RolePermission]] = relationship(
        "RolePermission",
        back_populates="role",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    # ── Table Args ───────────────────────────────────────────────────────
    __table_args__ = (
        {"comment": "Named roles for role-based access control"},
    )

    def __repr__(self) -> str:
        return f"<Role id={self.id} name={self.name!r}>"
