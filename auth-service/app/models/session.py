"""Session model.

Tracks active login sessions for users. Each session corresponds to
a successful login from a specific device/browser.

Key features:
- Tracks IP address and user agent for security visibility
- `revoked_at` for soft revocation (preserves audit trail)
- `refresh_token_family` groups refresh tokens in a rotation chain
- `last_used_at` tracks session activity for cleanup

Design decisions:
- Sessions are separate from refresh tokens: a session can have
  multiple refresh tokens over its lifetime (rotation)
- `device_info` is a structured JSONB field for flexible metadata
- Index on (user_id, revoked_at) for efficient active session queries
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Session(Base):
    """User login session tracking."""

    __tablename__ = "sessions"

    # ── Primary Key ──────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ── Foreign Keys ─────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Token Family ─────────────────────────────────────────────────────
    refresh_token_family: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Family ID grouping rotated refresh tokens",
    )

    # ── Client Information ───────────────────────────────────────────────
    ip_address: Mapped[str | None] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="Client IP address at login time",
    )
    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Full User-Agent header string",
    )
    device_info: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Parsed device info (device type, OS, browser)",
    )

    # ── Timestamps ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
        server_default="now()",
        comment="Session creation time (login time)",
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
        server_default="now()",
        comment="Last time this session was used",
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Session expiration time",
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the session was revoked (null = active)",
    )

    # ── Relationships ────────────────────────────────────────────────────
    user: Mapped[User] = relationship(
        "User",
        back_populates="sessions",
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        "RefreshToken",
        back_populates="session",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # ── Indexes ──────────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_sessions_user_active", "user_id", "revoked_at"),
        Index("ix_sessions_family", "refresh_token_family"),
        Index("ix_sessions_expires", "expires_at"),
        {"comment": "User login session tracking"},
    )

    @property
    def is_active(self) -> bool:
        """Check if session is active (not revoked and not expired)."""
        if self.revoked_at is not None:
            return False
        now = datetime.now(timezone.utc)
        return self.expires_at > now

    def __repr__(self) -> str:
        return f"<Session id={self.id} user_id={self.user_id}>"
