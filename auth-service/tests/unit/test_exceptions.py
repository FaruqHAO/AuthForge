"""Unit tests for the exception hierarchy.

Tests verify:
- Exception inheritance (all inherit from AuthBaseException)
- Status code mapping
- Error code mapping
- Default and custom messages
- Exception handler JSON response format
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.exceptions import (
    AccountDisabledError,
    AccountLockedError,
    AuthenticationError,
    AuthBaseException,
    AuthorizationError,
    ConflictError,
    DatabaseError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    InvalidResetTokenError,
    InvalidTokenError,
    InternalError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    RedisError,
    RefreshTokenReuseError,
    RefreshTokenRevokedError,
    RoleNotFoundError,
    TokenExpiredError,
    TokenError,
    UserNotFoundError,
    ValidationError,
    WeakPasswordError,
)


class TestExceptionHierarchy:
    """Tests for exception inheritance chain."""

    def test_all_inherit_from_auth_base(self):
        """Every custom exception should inherit from AuthBaseException."""
        exception_classes = [
            AuthenticationError,
            InvalidCredentialsError,
            AccountLockedError,
            AccountDisabledError,
            TokenExpiredError,
            TokenError,
            InvalidTokenError,
            RefreshTokenRevokedError,
            RefreshTokenReuseError,
            AuthorizationError,
            PermissionDeniedError,
            NotFoundError,
            UserNotFoundError,
            RoleNotFoundError,
            ConflictError,
            EmailAlreadyExistsError,
            ValidationError,
            WeakPasswordError,
            InvalidResetTokenError,
            RateLimitError,
            InternalError,
            DatabaseError,
            RedisError,
        ]
        for exc_class in exception_classes:
            assert issubclass(exc_class, AuthBaseException), (
                f"{exc_class.__name__} does not inherit from AuthBaseException"
            )

    def test_authentication_subclass(self):
        """Auth-specific errors should inherit from AuthenticationError."""
        assert issubclass(InvalidCredentialsError, AuthenticationError)
        assert issubclass(AccountLockedError, AuthenticationError)
        assert issubclass(AccountDisabledError, AuthenticationError)
        assert issubclass(TokenExpiredError, AuthenticationError)

    def test_token_subclass(self):
        """Token errors should inherit from TokenError."""
        assert issubclass(InvalidTokenError, TokenError)
        assert issubclass(RefreshTokenRevokedError, TokenError)
        assert issubclass(RefreshTokenReuseError, TokenError)

    def test_authorization_subclass(self):
        """Authorization errors should inherit from AuthorizationError."""
        assert issubclass(PermissionDeniedError, AuthorizationError)

    def test_not_found_subclass(self):
        """Not-found errors should inherit from NotFoundError."""
        assert issubclass(UserNotFoundError, NotFoundError)
        assert issubclass(RoleNotFoundError, NotFoundError)


class TestExceptionAttributes:
    """Tests for exception status codes, error codes, and messages."""

    def test_invalid_credentials_attributes(self):
        """InvalidCredentialsError should have 401 and proper error code."""
        exc = InvalidCredentialsError()
        assert exc.status_code == 401
        assert exc.error_code == "INVALID_CREDENTIALS"
        assert "email" in exc.message.lower() or "password" in exc.message.lower()

    def test_account_locked_attributes(self):
        """AccountLockedError should have 401 and lockout message."""
        exc = AccountLockedError()
        assert exc.status_code == 401
        assert exc.error_code == "ACCOUNT_LOCKED"

    def test_permission_denied_attributes(self):
        """PermissionDeniedError should have 403."""
        exc = PermissionDeniedError()
        assert exc.status_code == 403
        assert exc.error_code == "PERMISSION_DENIED"

    def test_user_not_found_attributes(self):
        """UserNotFoundError should have 404."""
        exc = UserNotFoundError()
        assert exc.status_code == 404
        assert exc.error_code == "USER_NOT_FOUND"

    def test_email_already_exists_attributes(self):
        """EmailAlreadyExistsError should have 409."""
        exc = EmailAlreadyExistsError()
        assert exc.status_code == 409
        assert exc.error_code == "EMAIL_ALREADY_EXISTS"

    def test_rate_limit_attributes(self):
        """RateLimitError should have 429."""
        exc = RateLimitError()
        assert exc.status_code == 429
        assert exc.error_code == "RATE_LIMIT_EXCEEDED"

    def test_database_error_attributes(self):
        """DatabaseError should have 500."""
        exc = DatabaseError()
        assert exc.status_code == 500
        assert exc.error_code == "DATABASE_ERROR"

    def test_custom_message(self):
        """Exceptions should accept custom messages."""
        exc = InvalidCredentialsError(message="Custom message")
        assert exc.message == "Custom message"

    def test_default_message(self):
        """Exceptions should use default message when none provided."""
        exc = InvalidCredentialsError()
        assert exc.message == InvalidCredentialsError.message


class TestExceptionHandlers:
    """Tests for exception handler JSON response format."""

    @pytest.mark.asyncio
    async def test_invalid_credentials_returns_401(self, client: AsyncClient):
        """InvalidCredentialsError should return 401 with error envelope."""
        from app.core.exceptions import InvalidCredentialsError
        from app.main import create_app
        from fastapi import APIRouter

        # Create a test endpoint that raises the exception
        test_router = APIRouter()

        @test_router.get("/test-error")
        async def raise_error():
            raise InvalidCredentialsError()

        app = create_app()
        app.include_router(test_router)

        from httpx import ASGITransport
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            response = await ac.get("/test-error")

        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert data["error"]["code"] == "INVALID_CREDENTIALS"
        assert "email" in data["error"]["message"].lower() or "password" in data["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_rate_limit_returns_429(self, client: AsyncClient):
        """RateLimitError should return 429 with error envelope."""
        from app.core.exceptions import RateLimitError
        from app.main import create_app
        from fastapi import APIRouter

        test_router = APIRouter()

        @test_router.get("/test-rate-limit")
        async def raise_rate_limit():
            raise RateLimitError()

        app = create_app()
        app.include_router(test_router)

        from httpx import ASGITransport
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            response = await ac.get("/test-rate-limit")

        assert response.status_code == 429
        data = response.json()
        assert data["success"] is False
        assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    @pytest.mark.asyncio
    async def test_unhandled_exception_returns_500(self, client: AsyncClient):
        """Unhandled exceptions should return 500 with generic message."""
        from app.main import create_app
        from fastapi import APIRouter

        test_router = APIRouter()

        @test_router.get("/test-unhandled")
        async def raise_unhandled():
            raise ValueError("Internal detail that should not leak")

        app = create_app()
        app.include_router(test_router)

        from httpx import ASGITransport
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            response = await ac.get("/test-unhandled")

        assert response.status_code == 500
        data = response.json()
        assert data["success"] is False
        assert data["error"]["code"] == "INTERNAL_ERROR"
        # Ensure internal details are NOT leaked
        assert "Internal detail" not in data["error"]["message"]
