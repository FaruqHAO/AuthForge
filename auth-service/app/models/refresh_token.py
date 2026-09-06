"""Refresh token model.

Stores hashed refresh tokens with chain/family tracking for:
- Token rotation: each use creates a new token, invalidating the old one
- Reuse detection: if a revoked token is reused, the entire family is killed
- Token family: groups tokens from the same login session

Design decisions:
- ONLY the SHA-256 hash of the refresh token is stored (never raw tokens)
- `token_hash` is unique — prevents duplicate tokens
- `parent_id` creates a linked list enabling chain validation
- `family_id` groups all tokens from one login session
- `is_revoked` for individual token revocation
- `rotated_at` tracks when the token was superseded by a new one
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RefreshToken(Base):
    """Refresh token with chain tracking for rotation and reuse detection."""

    __tablename__ = "refresh_tokens"

    # ── Primary Key ──────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ── Token ────────────────────────────────────────────────────────────
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        comment="SHA-256 hash of the raw refresh token",
    )

    # ── Foreign Keys ─────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ── Chain / Family Tracking ──────────────────────────────────────────
    family_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Token family ID (same across all rotations of one login)",
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"),
        nullable=True,
        comment="Previous token in this rotation chain",
    )

    # ── Status ───────────────────────────────────────────────────────────
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="false",
        comment="True = token has been revoked or rotated",
    )

    # ── Timestamps ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
        server_default="now()",
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Token expiration time",
    )
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this token was replaced by a new one",
    )

    # ── Relationships ────────────────────────────────────────────────────
    user: Mapped[User] = relationship(
        "User",
        back_populates="refresh_tokens",
    )
    session: Mapped[Session] = relationship(
        "Session",
        back_populates="refresh_tokens",
    )
    parent: Mapped[RefreshToken | None] = relationship(
        "RefreshToken",
        remote_side="RefreshToken.id",
        lazy="joined",
    )

    # ── Indexes ──────────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_session_id", "session_id"),
        Index("ix_refresh_tokens_family_id", "family_id"),
        Index("ix_refresh_tokens_expires", "expires_at"),
        {"comment": "Refresh tokens with chain tracking for rotation"},
    )

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        now = datetime.now(timezone.utc)
        return self.expires_at <= now

    @property
    def is_valid(self) -> bool:
        """Check if the token is usable (not revoked and not expired)."""
        return not self.is_revoked and not self.is_expired

    def __repr__(self) -> str:
        return f"<RefreshToken id={self.id} user_id={self.user_id}>"
