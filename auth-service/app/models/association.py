"""Association models for many-to-many relationships.

UserRole: Links users to roles. Tracks who assigned the role and when.
RolePermission: Links roles to permissions. Tracks who granted the permission.

Design decisions:
- Composite primary keys (user_id + role_id, role_id + permission_id)
  prevent duplicate assignments
- `assigned_at` / `granted_at` timestamps enable audit trails
- `assigned_by` / `granted_by` track the admin who made the change
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, PrimaryKeyConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRole(Base):
    """Association between User and Role."""

    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
        server_default="now()",
    )
    assigned_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who assigned this role",
    )

    # ── Relationships ────────────────────────────────────────────────────
    user: Mapped[User] = relationship(
        "User",
        back_populates="roles",
        foreign_keys=[user_id],
    )
    role: Mapped[Role] = relationship(
        "Role",
        back_populates="user_roles",
    )

    # ── Constraints ──────────────────────────────────────────────────────
    __table_args__ = (
        PrimaryKeyConstraint("user_id", "role_id"),
        {"comment": "User-to-role assignments"},
    )

    def __repr__(self) -> str:
        return f"<UserRole user_id={self.user_id} role_id={self.role_id}>"


class RolePermission(Base):
    """Association between Role and Permission."""

    __tablename__ = "role_permissions"

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
        server_default="now()",
    )
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who granted this permission",
    )

    # ── Relationships ────────────────────────────────────────────────────
    role: Mapped[Role] = relationship(
        "Role",
        back_populates="role_permissions",
    )
    permission: Mapped[Permission] = relationship(
        "Permission",
        back_populates="role_permissions",
    )

    # ── Constraints ──────────────────────────────────────────────────────
    __table_args__ = (
        PrimaryKeyConstraint("role_id", "permission_id"),
        {"comment": "Role-to-permission grants"},
    )

    def __repr__(self) -> str:
        return f"<RolePermission role_id={self.role_id} permission_id={self.permission_id}>"
