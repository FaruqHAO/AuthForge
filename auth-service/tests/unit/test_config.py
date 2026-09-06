"""Unit tests for application configuration.

Tests cover:
- Settings loading from environment variables
- Default values for optional settings
- Validation of required fields (secret keys)
- Nested settings groups (database, redis, jwt, etc.)
- Property accessors (is_production, is_testing)
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from app.core.config import (
    CORSSettings,
    CookieSettings,
    DatabaseSettings,
    JWTSettings,
    RateLimitSettings,
    RedisSettings,
    Settings,
    get_settings,
)


class TestDatabaseSettings:
    """Tests for PostgreSQL configuration."""

    def test_default_url(self):
        """Default URL should use asyncpg driver."""
        settings = DatabaseSettings()
        assert settings.url.startswith("postgresql+asyncpg://")

    def test_pool_size_bounds(self):
        """Pool size should be between 1 and 100."""
        settings = DatabaseSettings(pool_size=1)
        assert settings.pool_size == 1

        with pytest.raises(Exception):
            DatabaseSettings(pool_size=0)

    def test_invalid_url_rejected(self):
        """Non-asyncpg URLs should be rejected."""
        with pytest.raises(Exception):
            DatabaseSettings(url="sqlite:///test.db")

    def test_echo_default_false(self):
        """SQL echo should be off by default."""
        settings = DatabaseSettings()
        assert settings.echo is False


class TestRedisSettings:
    """Tests for Redis configuration."""

    def test_default_url(self):
        """Default Redis URL should point to localhost."""
        settings = RedisSettings()
        assert settings.url == "redis://localhost:6379/0"

    def test_max_connections_positive(self):
        """Max connections should be positive."""
        settings = RedisSettings(max_connections=10)
        assert settings.max_connections == 10


class TestJWTSettings:
    """Tests for JWT configuration."""

    def test_secret_key_required(self):
        """JWT secret key must be provided."""
        with pytest.raises(Exception):
            JWTSettings(secret_key="")

    def test_secret_key_minimum_length(self):
        """JWT secret key must be at least 32 characters."""
        with pytest.raises(Exception):
            JWTSettings(secret_key="short")

    def test_valid_secret_key(self):
        """Valid secret key should be accepted."""
        settings = JWTSettings(secret_key="a" * 32)
        assert settings.secret_key == "a" * 32

    def test_default_algorithm(self):
        """Default algorithm should be HS256."""
        settings = JWTSettings(secret_key="a" * 32)
        assert settings.algorithm == "HS256"

    def test_access_token_expire_minutes(self):
        """Access token expiry should be configurable."""
        settings = JWTSettings(secret_key="a" * 32, access_token_expire_minutes=30)
        assert settings.access_token_expire_minutes == 30

    def test_refresh_token_expire_days(self):
        """Refresh token expiry should be configurable."""
        settings = JWTSettings(secret_key="a" * 32, refresh_token_expire_days=14)
        assert settings.refresh_token_expire_days == 14

    def test_issuer_default(self):
        """Default issuer should be 'auth-service'."""
        settings = JWTSettings(secret_key="a" * 32)
        assert settings.issuer == "auth-service"


class TestSMTPSettings:
    """Tests for SMTP configuration."""

    def test_not_configured_by_default(self):
        """SMTP should report as not configured when credentials are missing."""
        settings = SMTPSettings()
        assert settings.is_configured is False

    def test_configured_with_credentials(self):
        """SMTP should report as configured when credentials are set."""
        settings = SMTPSettings(
            host="smtp.example.com",
            username="user@example.com",
            password="secret",
        )
        assert settings.is_configured is True


class TestCORSSettings:
    """Tests for CORS configuration."""

    def test_default_origins(self):
        """Default origins should include common dev servers."""
        settings = CORSSettings()
        assert "http://localhost:4200" in settings.allowed_origins
        assert "http://localhost:3000" in settings.allowed_origins

    def test_credentials_allowed(self):
        """Credentials should be allowed by default."""
        settings = CORSSettings()
        assert settings.allow_credentials is True


class TestCookieSettings:
    """Tests for cookie configuration."""

    def test_disabled_by_default(self):
        """Cookie auth should be disabled by default."""
        settings = CookieSettings()
        assert settings.enabled is False

    def test_secure_default(self):
        """Secure flag should be False in development."""
        settings = CookieSettings()
        assert settings.secure is False

    def test_samesite_default(self):
        """SameSite should default to strict."""
        settings = CookieSettings()
        assert settings.samesite == "strict"


class TestRateLimitSettings:
    """Tests for rate limiting configuration."""

    def test_default_login_limit(self):
        """Default login rate limit should be 5/minute."""
        settings = RateLimitSettings()
        assert settings.login == "5/minute"

    def test_default_register_limit(self):
        """Default register rate limit should be 3/hour."""
        settings = RateLimitSettings()
        assert settings.register == "3/hour"


class TestSettings:
    """Tests for root Settings class."""

    def test_default_environment(self):
        """Default environment should be development."""
        settings = Settings(
            secret_key="a" * 32,
            jwt__secret_key="b" * 32,
        )
        assert settings.environment == "development"

    def test_is_production(self):
        """is_production should return True for production environment."""
        settings = Settings(
            environment="production",
            secret_key="a" * 32,
            jwt__secret_key="b" * 32,
        )
        assert settings.is_production is True

    def test_is_testing(self):
        """is_testing should return True for testing environment."""
        settings = Settings(
            environment="testing",
            secret_key="a" * 32,
            jwt__secret_key="b" * 32,
        )
        assert settings.is_testing is True

    def test_debug_mode(self):
        """Debug mode should be configurable."""
        settings = Settings(
            debug=True,
            secret_key="a" * 32,
            jwt__secret_key="b" * 32,
        )
        assert settings.debug is True

    def test_nested_settings_populated(self):
        """Nested settings should have default values."""
        settings = Settings(
            secret_key="a" * 32,
            jwt__secret_key="b" * 32,
        )
        assert settings.database is not None
        assert settings.redis is not None
        assert settings.jwt is not None
        assert settings.smtp is not None
        assert settings.cors is not None
        assert settings.cookie is not None
        assert settings.rate_limit is not None

    def test_settings_cache(self):
        """get_settings should return the same instance on repeated calls."""
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2

    def test_env_override(self):
        """Environment variables should override defaults."""
        with patch.dict(os.environ, {"APP_NAME": "Custom Auth Service"}):
            get_settings.cache_clear()
            try:
                settings = get_settings()
                assert settings.app_name == "Custom Auth Service"
            finally:
                get_settings.cache_clear()
