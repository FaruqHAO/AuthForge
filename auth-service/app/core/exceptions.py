"""Centralized exception hierarchy.

Every custom exception maps to an HTTP status code and an error code string.
The API exception handlers convert these into the standard JSON envelope:

    {
        "success": false,
        "error": {
            "code": "INVALID_CREDENTIALS",
            "message": "Invalid email or password"
        }
    }

Design decisions:
- Exception hierarchy allows catching broad categories (AuthenticationError)
  or specific errors (InvalidCredentialsError)
- Each exception carries both a user-facing message and an internal error code
- No stack traces or internal details are exposed to clients
- Exception messages are security-safe (no user enumeration, no token leakage)
"""

from __future__ import annotations

from http import HTTPStatus


class AuthBaseException(Exception):
    """Base exception for all auth service errors."""

    status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code: str = "INTERNAL_ERROR"
    message: str = "An unexpected error occurred"

    def __init__(
        self,
        message: str | None = None,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
    ) -> None:
        self.message = message or self.__class__.message
        if status_code is not None:
            self.status_code = status_code
        if error_code is not None:
            self.error_code = error_code
        super().__init__(self.message)


# ── Authentication Errors (401) ──────────────────────────────────────────


class AuthenticationError(AuthBaseException):
    """Base for authentication failures."""

    status_code = HTTPStatus.UNAUTHORIZED
    error_code = "AUTHENTICATION_ERROR"
    message = "Authentication failed"


class InvalidCredentialsError(AuthenticationError):
    """Wrong email or password. Generic message prevents user enumeration."""

    error_code = "INVALID_CREDENTIALS"
    message = "Invalid email or password"


class AccountLockedError(AuthenticationError):
    """Too many failed login attempts."""

    error_code = "ACCOUNT_LOCKED"
    message = "Account is temporarily locked due to too many failed login attempts"


class AccountDisabledError(AuthenticationError):
    """Account has been deactivated."""

    error_code = "ACCOUNT_DISABLED"
    message = "Account has been deactivated"


class EmailNotVerifiedError(AuthenticationError):
    """Email address has not been verified."""

    error_code = "EMAIL_NOT_VERIFIED"
    message = "Please verify your email address before logging in"


class TokenExpiredError(AuthenticationError):
    """Token has expired."""

    error_code = "TOKEN_EXPIRED"
    message = "Token has expired"


# ── Token Errors (401) ───────────────────────────────────────────────────


class TokenError(AuthBaseException):
    """Base for token-related errors."""

    status_code = HTTPStatus.UNAUTHORIZED
    error_code = "TOKEN_ERROR"
    message = "Token error"


class InvalidTokenError(TokenError):
    """Token is malformed or invalid."""

    error_code = "TOKEN_INVALID"
    message = "Invalid token"


class RefreshTokenRevokedError(TokenError):
    """Refresh token has been revoked."""

    error_code = "REFRESH_TOKEN_REVOKED"
    message = "Refresh token has been revoked"


class RefreshTokenReuseError(TokenError):
    """Refresh token reuse detected — possible token theft.

    When a revoked refresh token is reused, the entire token family
    is invalidated. The user must re-authenticate from scratch.
    """

    error_code = "REFRESH_TOKEN_REUSE_DETECTED"
    message = "Token reuse detected. Please log in again."


# ── Authorization Errors (403) ──────────────────────────────────────────


class AuthorizationError(AuthBaseException):
    """Base for authorization failures."""

    status_code = HTTPStatus.FORBIDDEN
    error_code = "AUTHORIZATION_ERROR"
    message = "Access denied"


class PermissionDeniedError(AuthorizationError):
    """User lacks a specific permission."""

    error_code = "PERMISSION_DENIED"
    message = "You do not have permission to perform this action"


class InsufficientPermissionsError(AuthorizationError):
    """User lacks the required role or permission level."""

    error_code = "INSUFFICIENT_PERMISSIONS"
    message = "Insufficient permissions for this operation"


# ── Not Found Errors (404) ──────────────────────────────────────────────


class NotFoundError(AuthBaseException):
    """Base for not-found errors."""

    status_code = HTTPStatus.NOT_FOUND
    error_code = "NOT_FOUND"
    message = "Resource not found"


class UserNotFoundError(NotFoundError):
    error_code = "USER_NOT_FOUND"
    message = "User not found"


class RoleNotFoundError(NotFoundError):
    error_code = "ROLE_NOT_FOUND"
    message = "Role not found"


class PermissionNotFoundError(NotFoundError):
    error_code = "PERMISSION_NOT_FOUND"
    message = "Permission not found"


class SessionNotFoundError(NotFoundError):
    error_code = "SESSION_NOT_FOUND"
    message = "Session not found"


# ── Conflict Errors (409) ───────────────────────────────────────────────


class ConflictError(AuthBaseException):
    """Base for resource conflict errors."""

    status_code = HTTPStatus.CONFLICT
    error_code = "CONFLICT"
    message = "Resource conflict"


class EmailAlreadyExistsError(ConflictError):
    error_code = "EMAIL_ALREADY_EXISTS"
    message = "An account with this email already exists"


class UsernameTakenError(ConflictError):
    error_code = "USERNAME_TAKEN"
    message = "This username is already taken"


# ── Validation Errors (422) ─────────────────────────────────────────────


class ValidationError(AuthBaseException):
    """Base for validation errors."""

    status_code = HTTPStatus.UNPROCESSABLE_ENTITY
    error_code = "VALIDATION_ERROR"
    message = "Validation error"


class WeakPasswordError(ValidationError):
    error_code = "WEAK_PASSWORD"
    message = "Password does not meet security requirements"


class InvalidResetTokenError(ValidationError):
    error_code = "INVALID_RESET_TOKEN"
    message = "Invalid or expired reset token"


class InvalidVerificationTokenError(ValidationError):
    error_code = "INVALID_VERIFICATION_TOKEN"
    message = "Invalid or expired verification token"


# ── Rate Limit Errors (429) ─────────────────────────────────────────────


class RateLimitError(AuthBaseException):
    """Too many requests."""

    status_code = HTTPStatus.TOO_MANY_REQUESTS
    error_code = "RATE_LIMIT_EXCEEDED"
    message = "Too many requests. Please try again later."


# ── Internal Errors (500) ───────────────────────────────────────────────


class InternalError(AuthBaseException):
    """Catch-all for unexpected internal errors."""

    status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "INTERNAL_ERROR"
    message = "An unexpected error occurred"


class DatabaseError(InternalError):
    error_code = "DATABASE_ERROR"
    message = "A database error occurred"


class RedisError(InternalError):
    error_code = "REDIS_ERROR"
    message = "A caching error occurred"
