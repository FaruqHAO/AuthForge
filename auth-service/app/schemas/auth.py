"""Authentication schemas.

Pydantic models for authentication API request/response validation.
These schemas enforce input validation and define the API contract.

Design decisions:
- Separate Request/Response schemas for each endpoint
- Never include password_hash in any response schema
- Use strong typing for email, password, and token fields
- Response schemas use the standard envelope format
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


# ── Request Schemas ──────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    """User registration request."""

    email: EmailStr = Field(
        ...,
        description="Valid email address",
        examples=["user@example.com"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (min 8 chars, must include upper, lower, digit, special)",
    )
    first_name: str | None = Field(
        default=None,
        max_length=100,
        description="First name",
    )
    last_name: str | None = Field(
        default=None,
        max_length=100,
        description="Last name",
    )
    username: str | None = Field(
        default=None,
        min_length=3,
        max_length=50,
        description="Optional display username",
    )


class LoginRequest(BaseModel):
    """User login request."""

    email: EmailStr = Field(
        ...,
        description="Registered email address",
    )
    password: str = Field(
        ...,
        description="Account password",
    )


class RefreshRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str = Field(
        ...,
        description="Valid refresh token",
    )


class ChangePasswordRequest(BaseModel):
    """Change password request (requires current password)."""

    current_password: str = Field(
        ...,
        description="Current password for verification",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password (min 8 chars)",
    )


class ForgotPasswordRequest(BaseModel):
    """Request password reset email."""

    email: EmailStr = Field(
        ...,
        description="Registered email address",
    )


class ResetPasswordRequest(BaseModel):
    """Reset password with token from email."""

    token: str = Field(
        ...,
        description="Password reset token from email",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password (min 8 chars)",
    )


class VerifyEmailRequest(BaseModel):
    """Verify email with token."""

    token: str = Field(
        ...,
        description="Email verification token",
    )


class ResendVerificationRequest(BaseModel):
    """Resend verification email."""

    email: EmailStr = Field(
        ...,
        description="Email address to resend verification",
    )


class UpdateProfileRequest(BaseModel):
    """Update user profile."""

    first_name: str | None = Field(
        default=None,
        max_length=100,
    )
    last_name: str | None = Field(
        default=None,
        max_length=100,
    )
    username: str | None = Field(
        default=None,
        min_length=3,
        max_length=50,
    )


# ── Response Schemas ─────────────────────────────────────────────────────


class TokenPairResponse(BaseModel):
    """Access and refresh token pair returned after login/refresh."""

    access_token: str = Field(description="JWT access token")
    refresh_token: str = Field(description="Refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Access token expiry in seconds")


class UserProfile(BaseModel):
    """User profile (safe to return in API responses)."""

    id: uuid.UUID
    email: str
    username: str | None
    first_name: str | None
    last_name: str | None
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login_at: datetime | None

    model_config = {"from_attributes": True}


class SessionInfo(BaseModel):
    """Session information for listing active sessions."""

    id: uuid.UUID
    ip_address: str | None
    user_agent: str | None
    device_info: str | None
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}


class RegisterResponse(BaseModel):
    """Registration response."""

    user: UserProfile
    message: str = Field(
        default="Registration successful. Please check your email to verify your account.",
    )


class LoginResponse(BaseModel):
    """Login response with tokens."""

    tokens: TokenPairResponse
    user: UserProfile
