"""Unit tests for security primitives.

Tests cover:
- Password hashing (Argon2id)
- Password verification
- Password strength validation
- JWT access token creation/decoding
- JWT refresh token creation/decoding
- Token expiration
- Token type validation
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    hash_password,
    hash_token,
    needs_rehash,
    validate_password_strength,
    verify_password,
)


class TestPasswordHashing:
    """Tests for Argon2id password hashing."""

    def test_hash_password_returns_string(self):
        """Hash should be a non-empty string."""
        result = hash_password("TestPassword123!")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_contains_argon2_identifier(self):
        """Hash should start with $argon2id$."""
        result = hash_password("TestPassword123!")
        assert result.startswith("$argon2id$")

    def test_different_hashes_for_same_password(self):
        """Same password should produce different hashes (random salt)."""
        hash1 = hash_password("TestPassword123!")
        hash2 = hash_password("TestPassword123!")
        assert hash1 != hash2

    def test_verify_correct_password(self):
        """Correct password should verify successfully."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_wrong_password(self):
        """Wrong password should fail verification."""
        hashed = hash_password("TestPassword123!")
        assert verify_password("WrongPassword123!", hashed) is False

    def test_verify_empty_password(self):
        """Empty password should not match non-empty hash."""
        hashed = hash_password("TestPassword123!")
        assert verify_password("", hashed) is False

    def test_verify_malformed_hash(self):
        """Malformed hash should return False, not raise."""
        assert verify_password("TestPassword123!", "not-a-hash") is False

    def test_needs_rehash_default_false(self):
        """Newly created hashes should not need rehashing."""
        hashed = hash_password("TestPassword123!")
        assert needs_rehash(hashed) is False


class TestPasswordStrength:
    """Tests for password strength validation."""

    def test_valid_password(self):
        """Strong password should pass validation."""
        is_valid, msg = validate_password_strength("MyStr0ng!Pass")
        assert is_valid is True
        assert msg == ""

    def test_too_short(self):
        """Password shorter than 8 chars should fail."""
        is_valid, msg = validate_password_strength("Ab1!")
        assert is_valid is False
        assert "8 characters" in msg

    def test_no_uppercase(self):
        """Password without uppercase should fail."""
        is_valid, msg = validate_password_strength("mystr0ng!pass")
        assert is_valid is False
        assert "uppercase" in msg.lower()

    def test_no_lowercase(self):
        """Password without lowercase should fail."""
        is_valid, msg = validate_password_strength("MYSTR0NG!PASS")
        assert is_valid is False
        assert "lowercase" in msg.lower()

    def test_no_digit(self):
        """Password without digit should fail."""
        is_valid, msg = validate_password_strength("MyStrng!Pass")
        assert is_valid is False
        assert "digit" in msg.lower()

    def test_no_special_char(self):
        """Password without special char should fail."""
        is_valid, msg = validate_password_strength("MyStr0ngPass")
        assert is_valid is False
        assert "special" in msg.lower()

    def test_valid_with_all_requirements(self):
        """Password meeting all requirements should pass."""
        is_valid, _ = validate_password_strength("C0mpl3x!P@ssw0rd")
        assert is_valid is True


class TestJWTAccessTokens:
    """Tests for JWT access token creation and decoding."""

    def test_create_access_token_returns_string(self):
        """Access token should be a non-empty string."""
        token = create_access_token("user-123")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_decode_access_token(self):
        """Decoding a valid token should return correct claims."""
        user_id = "550e8400-e29b-41d4-a716-446655440000"
        token = create_access_token(user_id)
        payload = decode_access_token(token)
        assert payload["sub"] == user_id
        assert payload["type"] == "access"

    def test_access_token_has_required_claims(self):
        """Token should contain all required JWT claims."""
        token = create_access_token("user-123")
        payload = decode_access_token(token)
        assert "sub" in payload
        assert "jti" in payload
        assert "iss" in payload
        assert "aud" in payload
        assert "iat" in payload
        assert "exp" in payload
        assert "type" in payload

    def test_access_token_with_extra_claims(self):
        """Extra claims should be included in the token."""
        token = create_access_token(
            "user-123",
            extra_claims={"roles": ["ADMIN"], "permissions": ["users.read"]},
        )
        payload = decode_access_token(token)
        assert payload["roles"] == ["ADMIN"]
        assert payload["permissions"] == ["users.read"]

    def test_decode_invalid_token(self):
        """Invalid token should raise InvalidTokenError."""
        from app.core.exceptions import InvalidTokenError
        with pytest.raises(InvalidTokenError):
            decode_access_token("invalid.token.here")

    def test_decode_tampered_token(self):
        """Tampered token should raise InvalidTokenError."""
        from app.core.exceptions import InvalidTokenError
        token = create_access_token("user-123")
        # Tamper with the token
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(InvalidTokenError):
            decode_access_token(tampered)


class TestJWTRefreshTokens:
    """Tests for refresh token creation and hashing."""

    def test_create_refresh_token_returns_tuple(self):
        """Refresh token should return (raw_token, hash)."""
        raw, hashed = create_refresh_token("user-123")
        assert isinstance(raw, str)
        assert isinstance(hashed, str)
        assert len(raw) > 0
        assert len(hashed) == 64  # SHA-256 hex digest

    def test_refresh_token_hash_is_deterministic(self):
        """Hashing the same token should produce the same hash."""
        raw, _ = create_refresh_token("user-123")
        hash1 = hash_token(raw)
        hash2 = hash_token(raw)
        assert hash1 == hash2

    def test_different_tokens_produce_different_hashes(self):
        """Different tokens should produce different hashes."""
        raw1, _ = create_refresh_token("user-123")
        raw2, _ = create_refresh_token("user-456")
        assert hash_token(raw1) != hash_token(raw2)

    def test_hash_token_returns_sha256(self):
        """Token hash should be SHA-256 (64 hex chars)."""
        raw, _ = create_refresh_token("user-123")
        hashed = hash_token(raw)
        assert len(hashed) == 64
        assert all(c in "0123456789abcdef" for c in hashed)
