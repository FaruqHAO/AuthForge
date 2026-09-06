"""Unit tests for authentication schemas.

Tests cover:
- Request schema validation
- Response schema construction
- Field constraints (email, password length, etc.)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    TokenPairResponse,
    UpdateProfileRequest,
    UserProfile,
)


class TestRegisterRequest:
    """Tests for registration request schema."""

    def test_valid_registration(self):
        """Valid registration data should pass validation."""
        req = RegisterRequest(
            email="user@example.com",
            password="StrongPass123!",
        )
        assert req.email == "user@example.com"
        assert req.first_name is None

    def test_valid_with_optional_fields(self):
        """Registration with all optional fields should work."""
        req = RegisterRequest(
            email="user@example.com",
            password="StrongPass123!",
            first_name="John",
            last_name="Doe",
            username="johndoe",
        )
        assert req.first_name == "John"
        assert req.username == "johndoe"

    def test_invalid_email(self):
        """Invalid email should raise validation error."""
        with pytest.raises(ValidationError):
            RegisterRequest(email="not-an-email", password="StrongPass123!")

    def test_password_too_short(self):
        """Password shorter than 8 chars should fail."""
        with pytest.raises(ValidationError):
            RegisterRequest(email="user@example.com", password="Ab1!")

    def test_password_too_long(self):
        """Password longer than 128 chars should fail."""
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="user@example.com",
                password="A" * 129 + "1!",
            )


class TestLoginRequest:
    """Tests for login request schema."""

    def test_valid_login(self):
        """Valid login data should pass validation."""
        req = LoginRequest(
            email="user@example.com",
            password="anypassword",
        )
        assert req.email == "user@example.com"

    def test_invalid_email(self):
        """Invalid email should raise validation error."""
        with pytest.raises(ValidationError):
            LoginRequest(email="invalid", password="password")


class TestTokenPairResponse:
    """Tests for token pair response schema."""

    def test_token_pair_structure(self):
        """Token pair should have all required fields."""
        resp = TokenPairResponse(
            access_token="eyJ...",
            refresh_token="abc123",
            token_type="bearer",
            expires_in=900,
        )
        assert resp.token_type == "bearer"
        assert resp.expires_in == 900


class TestUserProfile:
    """Tests for user profile response schema."""

    def test_from_attributes(self):
        """Profile should be constructable from ORM model attributes."""
        user_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        profile = UserProfile(
            id=user_id,
            email="user@example.com",
            username="johndoe",
            first_name="John",
            last_name="Doe",
            is_active=True,
            is_verified=True,
            created_at=now,
            last_login_at=now,
        )
        assert profile.id == user_id
        assert profile.email == "user@example.com"


class TestUpdateProfileRequest:
    """Tests for profile update schema."""

    def test_empty_update(self):
        """Empty update should be valid (no fields required)."""
        req = UpdateProfileRequest()
        assert req.first_name is None
        assert req.last_name is None
        assert req.username is None

    def test_partial_update(self):
        """Partial update should work."""
        req = UpdateProfileRequest(first_name="Jane")
        assert req.first_name == "Jane"
        assert req.last_name is None
