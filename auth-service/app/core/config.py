"""Application configuration using Pydantic Settings.

All secrets are loaded from environment variables. This module provides
a single cached settings instance for the entire application.

Design decisions:
- Nested settings classes group related config (DB, Redis, JWT, etc.)
- lru_cache ensures settings are parsed once per process
- Case-insensitive env vars for flexibility across platforms
- Validation via Pydantic field constraints (min lengths, value ranges)
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """PostgreSQL connection configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DATABASE_",
        env_file_encoding="utf-8",
    )

    url: str = Field(
        default="postgresql+asyncpg://auth_user:auth_password@localhost:5432/auth_db",
        description="Async SQLAlchemy database URL",
    )
    echo: bool = Field(
        default=False,
        description="Log all SQL statements (dev only)",
    )
    pool_size: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Connection pool size",
    )
    max_overflow: int = Field(
        default=10,
        ge=0,
        le=200,
        description="Max overflow connections beyond pool_size",
    )

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        if not v.startswith(("postgresql+asyncpg://", "postgresql://")):
            msg = (
                "DATABASE_URL must use asyncpg driver: "
                "postgresql+asyncpg://..."
            )
            raise ValueError(msg)
        return v


class RedisSettings(BaseSettings):
    """Redis connection configuration.

    Redis is used for:
    - Rate limiting (sliding window counters)
    - Failed login attempt tracking (fast atomic increments)
    - Distributed locks (token rotation race conditions)
    """

    model_config = SettingsConfigDict(
        env_prefix="REDIS_",
        env_file_encoding="utf-8",
    )

    url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )
    max_connections: int = Field(
        default=20,
        ge=1,
        description="Maximum connections in pool",
    )


class JWTSettings(BaseSettings):
    """JWT token configuration.

    Token lifetime trade-offs:
    - Access token: 15 minutes balances security vs UX. Short enough to limit
      blast radius of token theft, long enough to avoid excessive refresh calls.
    - Refresh token: 7 days balances security vs UX. Users shouldn't re-login
      every few days, but tokens shouldn't live for months.

    Algorithm choice:
    - HS256 (symmetric) is sufficient when the same service issues and verifies.
    - RS256 (asymmetric) is better for multi-service setups where verification
      happens on different services without sharing the signing key.
    """

    model_config = SettingsConfigDict(
        env_prefix="JWT_",
        env_file_encoding="utf-8",
    )

    secret_key: str = Field(
        ...,
        min_length=32,
        description="Secret key for signing JWTs (min 32 chars)",
    )
    algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256 or RS256)",
    )
    access_token_expire_minutes: int = Field(
        default=15,
        ge=1,
        le=60,
        description="Access token lifetime in minutes",
    )
    refresh_token_expire_days: int = Field(
        default=7,
        ge=1,
        le=90,
        description="Refresh token lifetime in days",
    )

    issuer: str = Field(
        default="auth-service",
        description="JWT issuer claim",
    )
    audience: str = Field(
        default="auth-service",
        description="JWT audience claim",
    )


class SMTPSettings(BaseSettings):
    """SMTP email configuration.

    Email is used for:
    - Email verification after registration
    - Password reset requests
    - Security notifications (account locked, etc.)
    """

    model_config = SettingsConfigDict(
        env_prefix="SMTP_",
        env_file_encoding="utf-8",
    )

    host: str = Field(default="localhost")
    port: int = Field(default=587)
    username: str = Field(default="")
    password: str = Field(default="")
    from_address: str = Field(
        default="noreply@auth-service.local",
    )
    use_tls: bool = Field(default=True)

    @property
    def is_configured(self) -> bool:
        """Check if SMTP has meaningful configuration (not just defaults)."""
        return bool(self.host and self.username and self.password)


class CORSSettings(BaseSettings):
    """CORS configuration.

    Security note: In production with credentials, never use allow_origins=["*"].
    Always specify explicit allowed origins.
    """

    model_config = SettingsConfigDict(
        env_prefix="CORS_",
        env_file_encoding="utf-8",
    )

    allowed_origins: list[str] = Field(
        default=["http://localhost:4200", "http://localhost:3000"],
        description="Comma-separated list of allowed origins",
    )
    allow_credentials: bool = Field(
        default=True,
        description="Allow cookies and auth headers",
    )
    allow_methods: list[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    )
    allow_headers: list[str] = Field(
        default=["*"],
    )


class CookieSettings(BaseSettings):
    """Cookie-based authentication configuration.

    For browser apps (Angular), secure HttpOnly cookies are preferred over
    localStorage tokens because:
    - HttpOnly: JavaScript cannot access the token (XSS protection)
    - Secure: Only sent over HTTPS
    - SameSite: Prevents CSRF by defaulting to Strict

    Trade-off: Cookies are domain-bound and don't work for mobile apps.
    Mobile apps (Flutter) use Bearer tokens in Authorization header.
    """

    model_config = SettingsConfigDict(
        env_prefix="COOKIE_",
        env_file_encoding="utf-8",
    )

    enabled: bool = Field(
        default=False,
        description="Enable cookie-based authentication",
    )
    domain: str = Field(
        default="localhost",
        description="Cookie domain",
    )
    secure: bool = Field(
        default=False,
        description="Set Secure flag (must be true in production)",
    )
    samesite: Literal["strict", "lax", "none"] = Field(
        default="strict",
        description="Cookie SameSite policy",
    )
    max_age: int = Field(
        default=60 * 60 * 24 * 7,  # 7 days in seconds
        description="Cookie max age in seconds",
    )


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration.

    Format: "count/period" where period is minute, hour, or day.
    Stored in Redis for atomic operations and automatic expiry.
    """

    model_config = SettingsConfigDict(
        env_prefix="RATE_LIMIT_",
        env_file_encoding="utf-8",
    )

    login: str = Field(
        default="5/minute",
        description="Max login attempts per window",
    )
    register: str = Field(
        default="3/hour",
        description="Max registration attempts per window",
    )
    password_reset: str = Field(
        default="3/hour",
        description="Max password reset requests per window",
    )
    general: str = Field(
        default="100/minute",
        description="General API rate limit per user",
    )


class Settings(BaseSettings):
    """Root application settings.

    Aggregates all sub-settings. Loaded once per process via lru_cache.
    All values come from environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="Auth Service")
    app_version: str = Field(default="0.1.0")
    environment: Literal["development", "testing", "staging", "production"] = Field(
        default="development",
    )
    debug: bool = Field(default=False)
    secret_key: str = Field(
        default="change-me-to-a-random-64-char-hex-string",
        min_length=32,
    )

    # Nested settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)
    smtp: SMTPSettings = Field(default_factory=SMTPSettings)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    cookie: CookieSettings = Field(default_factory=CookieSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)

    @model_validator(mode="after")
    def validate_deployment_secrets(self) -> Settings:
        if self.environment in {"staging", "production"}:
            if self.secret_key.startswith("change-me") or self.jwt.secret_key.startswith("change-me"):
                raise ValueError("Set unique SECRET_KEY and JWT_SECRET_KEY before deployment")
            if self.secret_key == self.jwt.secret_key:
                raise ValueError("SECRET_KEY and JWT_SECRET_KEY must be different")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_testing(self) -> bool:
        return self.environment == "testing"


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings.

    Settings are parsed once on first call, then reused for the lifetime
    of the process. Call get_settings.cache_clear() in tests to reset.
    """
    return Settings()


# Convenience alias
settings = get_settings()
