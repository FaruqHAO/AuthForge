"""Unit tests for audit logging service.

Tests cover:
- Event logging
- Metadata sanitization
- Event type constants
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from app.services.audit_service import AuditService, AuditEvents


@pytest.fixture
def mock_session():
    """Mock async database session."""
    session = AsyncMock()
    session.add = AsyncMock()
    session.flush = AsyncMock()
    return session


@pytest.fixture
def audit_service(mock_session):
    """Create AuditService with mocked session."""
    return AuditService(mock_session)


class TestAuditLogging:
    """Tests for audit event logging."""

    @pytest.mark.asyncio
    async def test_log_event(self, audit_service):
        """Logging an event should create an AuditLog record."""
        result = await audit_service.log(
            AuditEvents.LOGIN_SUCCESS,
            user_id="user-123",
            ip_address="127.0.0.1",
            user_agent="TestAgent/1.0",
        )
        audit_service.session.add.assert_called_once()
        audit_service.session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_with_metadata(self, audit_service):
        """Logging with metadata should store it."""
        metadata = {"email": "user@example.com", "attempt": 1}
        result = await audit_service.log(
            AuditEvents.LOGIN_FAILED,
            user_id="user-123",
            metadata=metadata,
        )
        audit_service.session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_metadata_sanitization(self, audit_service):
        """Sensitive fields should be removed from metadata."""
        metadata = {
            "email": "user@example.com",
            "password": "secret123",
            "access_token": "token-value",
            "normal_field": "safe-value",
        }
        result = await audit_service.log(
            AuditEvents.LOGIN_FAILED,
            metadata=metadata,
        )

        # Get the AuditLog object that was added
        call_args = audit_service.session.add.call_args
        audit_log = call_args[0][0]

        # Check that sensitive fields were removed
        assert "password" not in audit_log.metadata_json
        assert "access_token" not in audit_log.metadata_json
        assert "email" in audit_log.metadata_json
        assert "normal_field" in audit_log.metadata_json

    @pytest.mark.asyncio
    async def test_log_none_metadata(self, audit_service):
        """Logging with None metadata should work."""
        result = await audit_service.log(
            AuditEvents.LOGOUT,
            user_id="user-123",
        )
        audit_service.session.add.assert_called_once()


class TestAuditEvents:
    """Tests for audit event constants."""

    def test_event_constants_exist(self):
        """All event constants should be defined."""
        assert AuditEvents.USER_REGISTERED == "USER_REGISTERED"
        assert AuditEvents.LOGIN_SUCCESS == "LOGIN_SUCCESS"
        assert AuditEvents.LOGIN_FAILED == "LOGIN_FAILED"
        assert AuditEvents.LOGOUT == "LOGOUT"
        assert AuditEvents.PASSWORD_CHANGED == "PASSWORD_CHANGED"
        assert AuditEvents.PASSWORD_RESET == "PASSWORD_RESET"
        assert AuditEvents.EMAIL_VERIFIED == "EMAIL_VERIFIED"
        assert AuditEvents.REFRESH_TOKEN_ROTATED == "REFRESH_TOKEN_ROTATED"
        assert AuditEvents.REFRESH_TOKEN_REUSE_DETECTED == "REFRESH_TOKEN_REUSE_DETECTED"
        assert AuditEvents.ACCOUNT_LOCKED == "ACCOUNT_LOCKED"
        assert AuditEvents.ROLE_ASSIGNED == "ROLE_ASSIGNED"
        assert AuditEvents.ROLE_REMOVED == "ROLE_REMOVED"
        assert AuditEvents.PERMISSION_CHANGED == "PERMISSION_CHANGED"
        assert AuditEvents.SESSION_REVOKED == "SESSION_REVOKED"
