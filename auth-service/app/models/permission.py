"""Permission model.

Represents a fine-grained permission in the format "resource.action":
- users.read, users.create, users.update, users.delete
- tickets.read, tickets.create, tickets.update, tickets.delete
- reports.read

Permissions are assigned to roles, and users inherit permissions
through their roles. Authorization checks use permission strings,
NOT role names.

Design decisions:
- Permission name is the canonical identifier (unique, indexed)
- resource + action fields enable programmatic permission queries
  (e.g., "show all permissions for the 'tickets' resource")
- Hard delete acceptable (permissions are configuration)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Permission(Base):
    """Fine-grained permission entity."""

    __tablename__ = "permissions"

    # ── Primary Key ──────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ── Identity ─────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Canonical permission name (e.g., tickets.delete)",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable description",
    )
    resource: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Resource this permission applies to (e.g., users, tickets)",
    )
    action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Action allowed (e.g., read, create, update, delete)",
    )

    # ── Timestamps ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
        server_default="now()",
    )

    # ── Relationships ────────────────────────────────────────────────────
    role_permissions: Mapped[list[RolePermission]] = relationship(
        "RolePermission",
        back_populates="permission",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # ── Indexes ──────────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_permissions_resource_action", "resource", "action"),
        {"comment": "Fine-grained permissions for authorization"},
    )

    def __repr__(self) -> str:
        return f"<Permission id={self.id} name={self.name!r}>"
