"""Audit log model.

Tracks security-sensitive events for compliance and incident response.
Append-only: records are never updated or deleted.

Events tracked:
- USER_REGISTERED, LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT
- PASSWORD_CHANGED, PASSWORD_RESET, EMAIL_VERIFIED
- REFRESH_TOKEN_ROTATED, REFRESH_TOKEN_REUSE_DETECTED
- ACCOUNT_LOCKED, ROLE_ASSIGNED, ROLE_REMOVED
- PERMISSION_CHANGED, SESSION_REVOKED

Security rules:
- Never store: passwords, raw tokens, password reset tokens, verification tokens
- Store: event type, user IDs, IP address, user agent, structured metadata
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    """Append-only audit log for security events."""

    __tablename__ = "audit_logs"

    # ── Primary Key ──────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ── Event ────────────────────────────────────────────────────────────
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Event type (e.g., LOGIN_SUCCESS, PASSWORD_CHANGED)",
    )

    # ── Actors ───────────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who triggered the event",
    )
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who was the target of the event (e.g., admin updating another user)",
    )

    # ── Client Information ───────────────────────────────────────────────
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        comment="Client IP address",
    )
    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Client User-Agent header",
    )

    # ── Metadata ─────────────────────────────────────────────────────────
    metadata_json: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Structured event metadata (never contains secrets)",
    )

    # ── Timestamp ────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
        server_default="now()",
        index=True,
    )

    # ── Relationships ────────────────────────────────────────────────────
    user: Mapped[User | None] = relationship(
        "User",
        back_populates="audit_logs",
        foreign_keys=[user_id],
    )

    # ── Indexes ──────────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_audit_logs_user_created", "user_id", "created_at"),
        {"comment": "Append-only security audit log"},
    )

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event={self.event_type!r}>"
