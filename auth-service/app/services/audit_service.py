"""Audit logging service.

Tracks security-sensitive events for compliance and incident response.
Events are stored in the audit_logs table (append-only).

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

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class AuditService:
    """Service for recording security audit events."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def log(
        self,
        event_type: str,
        *,
        user_id: Any = None,
        target_user_id: Any = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Record a security event.

        Args:
            event_type: Event type constant (e.g., LOGIN_SUCCESS)
            user_id: User who triggered the event
            target_user_id: User who was the target (for admin actions)
            ip_address: Client IP address
            user_agent: Client User-Agent header
            metadata: Structured event data (never contains secrets)

        Returns:
            Created AuditLog record
        """
        # Sanitize metadata — never log secrets
        safe_metadata = self._sanitize_metadata(metadata)

        audit_log = AuditLog(
            event_type=event_type,
            user_id=user_id,
            target_user_id=target_user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata_json=safe_metadata,
        )
        self.session.add(audit_log)
        await self.session.flush()

        logger.info(
            "Audit event: %s (user=%s, ip=%s)",
            event_type,
            user_id,
            ip_address,
        )

        return audit_log

    def _sanitize_metadata(
        self, metadata: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """Remove sensitive fields from metadata before storage.

        Never log: passwords, tokens, secrets, PII that isn't needed.
        """
        if metadata is None:
            return None

        sensitive_keys = {
            "password",
            "password_hash",
            "token",
            "access_token",
            "refresh_token",
            "secret",
            "api_key",
            "reset_token",
            "verification_token",
        }

        return {
            k: v
            for k, v in metadata.items()
            if k.lower() not in sensitive_keys
        }


# ── Event Type Constants ─────────────────────────────────────────────────

class AuditEvents:
    """Audit event type constants."""

    USER_REGISTERED = "USER_REGISTERED"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PASSWORD_RESET = "PASSWORD_RESET"
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    REFRESH_TOKEN_ROTATED = "REFRESH_TOKEN_ROTATED"
    REFRESH_TOKEN_REUSE_DETECTED = "REFRESH_TOKEN_REUSE_DETECTED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ROLE_ASSIGNED = "ROLE_ASSIGNED"
    ROLE_REMOVED = "ROLE_REMOVED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    SESSION_REVOKED = "SESSION_REVOKED"
