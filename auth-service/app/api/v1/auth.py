"""Authentication API routes.

Endpoints:
- POST /auth/register — Create new account
- POST /auth/login — Authenticate and get tokens
- POST /auth/logout — Revoke current session
- POST /auth/refresh — Rotate refresh token
- GET  /auth/me — Get current user profile
- PUT  /auth/me — Update profile
- POST /auth/change-password — Change password
- POST /auth/forgot-password — Request password reset (Phase 5)
- POST /auth/reset-password — Reset password with token (Phase 5)
- POST /auth/verify-email — Verify email (Phase 5)
- POST /auth/resend-verification — Resend verification email (Phase 5)
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.dependencies import get_db
from app.core.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
)
from app.core.security import decode_access_token
from app.api.schemas import ErrorResponse, SuccessResponse
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    ResetPasswordRequest,
    TokenPairResponse,
    UpdateProfileRequest,
    UserProfile,
    VerifyEmailRequest,
)
from app.services.auth_service import AuthService

router = APIRouter()


# ── Authentication Dependencies ──────────────────────────────────────────


async def get_current_user_id(
    request: Request,
    authorization: str | None = Header(default=None),
    access_token_cookie: str | None = Cookie(default=None, alias="access_token"),
    settings: Settings = Depends(get_settings),
) -> uuid.UUID:
    """Extract and validate the current user's ID from the request.

    Supports both Bearer token and cookie authentication.
    The token is validated (signature, expiration, type) and the
    user ID is extracted from the 'sub' claim.

    Raises:
        InvalidTokenError: If no valid token is provided
        TokenExpiredError: If the token has expired
    """
    token = None

    # Try Bearer token first
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    # Fall back to cookie
    elif access_token_cookie:
        token = access_token_cookie

    if not token:
        raise InvalidTokenError(message="Authentication required")

    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise InvalidTokenError(message="Token missing user ID")

    try:
        return uuid.UUID(user_id)
    except ValueError:
        raise InvalidTokenError(message="Invalid user ID in token")


async def get_auth_service(
    db: AsyncSession = Depends(get_db),
) -> AuthService:
    """Dependency that provides an AuthService instance."""
    return AuthService(db)


# ── Routes ───────────────────────────────────────────────────────────────


@router.post(
    "/register",
    response_model=SuccessResponse[RegisterResponse],
    status_code=201,
    summary="Register new user",
    description="Create a new user account. Returns user profile.",
    responses={
        409: {"model": ErrorResponse, "description": "Email already exists"},
        422: {"model": ErrorResponse, "description": "Weak password"},
    },
)
async def register(
    body: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[RegisterResponse]:
    """Register a new user account."""
    user = await auth_service.register(
        email=body.email,
        password=body.password,
        first_name=body.first_name,
        last_name=body.last_name,
        username=body.username,
    )

    return SuccessResponse(
        data=RegisterResponse(
            user=UserProfile.model_validate(user),
            message="Registration successful. Please check your email to verify your account.",
        ),
        message="Registration successful",
    )


@router.post(
    "/login",
    response_model=SuccessResponse[LoginResponse],
    summary="Login",
    description="Authenticate with email and password. Returns token pair.",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        423: {"model": ErrorResponse, "description": "Account locked"},
    },
)
async def login(
    body: LoginRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
    settings: Settings = Depends(get_settings),
) -> SuccessResponse[LoginResponse]:
    """Authenticate a user and return tokens."""
    # Get client info for session tracking
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    user, access_token, refresh_token = await auth_service.login(
        email=body.email,
        password=body.password,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    response = SuccessResponse(
        data=LoginResponse(
            tokens=TokenPairResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                expires_in=settings.jwt.access_token_expire_minutes * 60,
            ),
            user=UserProfile.model_validate(user),
        ),
        message="Login successful",
    )

    return response


@router.post(
    "/logout",
    response_model=SuccessResponse[None],
    summary="Logout current session",
    description="Revoke the current session and refresh token.",
)
async def logout(
    user_id: uuid.UUID = Depends(get_current_user_id),
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[None]:
    """Logout from the current session."""
    # Note: session_id would come from the token or request context
    # For now, we'll need to find the active session
    await auth_service.logout_all(user_id)
    return SuccessResponse(message="Logged out successfully")


@router.post(
    "/refresh",
    response_model=SuccessResponse[TokenPairResponse],
    summary="Refresh access token",
    description="Rotate refresh token and get new token pair.",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid or revoked token"},
    },
)
async def refresh_token(
    body: RefreshRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
    settings: Settings = Depends(get_settings),
) -> SuccessResponse[TokenPairResponse]:
    """Refresh the access token using a refresh token."""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    new_access, new_refresh = await auth_service.refresh_tokens(
        body.refresh_token,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return SuccessResponse(
        data=TokenPairResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            token_type="bearer",
            expires_in=settings.jwt.access_token_expire_minutes * 60,
        ),
        message="Tokens refreshed successfully",
    )


@router.get(
    "/me",
    response_model=SuccessResponse[UserProfile],
    summary="Get current user",
    description="Returns the authenticated user's profile.",
)
async def get_me(
    user_id: uuid.UUID = Depends(get_current_user_id),
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[UserProfile]:
    """Get the current user's profile."""
    user = await auth_service.get_current_user(user_id)
    return SuccessResponse(
        data=UserProfile.model_validate(user),
        message="User profile retrieved",
    )


@router.put(
    "/me",
    response_model=SuccessResponse[UserProfile],
    summary="Update profile",
    description="Update the authenticated user's profile.",
)
async def update_me(
    body: UpdateProfileRequest,
    user_id: uuid.UUID = Depends(get_current_user_id),
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[UserProfile]:
    """Update the current user's profile."""
    user = await auth_service.update_profile(
        user_id,
        first_name=body.first_name,
        last_name=body.last_name,
        username=body.username,
    )
    return SuccessResponse(
        data=UserProfile.model_validate(user),
        message="Profile updated successfully",
    )


@router.post(
    "/change-password",
    response_model=SuccessResponse[None],
    summary="Change password",
    description="Change the current user's password. Requires current password.",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid current password"},
        422: {"model": ErrorResponse, "description": "Weak new password"},
    },
)
async def change_password(
    body: ChangePasswordRequest,
    user_id: uuid.UUID = Depends(get_current_user_id),
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[None]:
    """Change the current user's password."""
    await auth_service.change_password(
        user_id,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    return SuccessResponse(message="Password changed successfully. All sessions have been invalidated.")


# ── Placeholder endpoints for Phase 5 ───────────────────────────────────


@router.post(
    "/forgot-password",
    response_model=SuccessResponse[None],
    summary="Request password reset",
    description="Send a password reset email. Always returns success to prevent user enumeration.",
)
async def forgot_password(
    body: ForgotPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[None]:
    """Request a password reset email."""
    # Phase 5: Send reset email if user exists
    # Always return success to prevent user enumeration
    return SuccessResponse(
        message="If the email exists, a password reset link has been sent."
    )


@router.post(
    "/reset-password",
    response_model=SuccessResponse[None],
    summary="Reset password",
    description="Reset password using token from email.",
)
async def reset_password(
    body: ResetPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[None]:
    """Reset password with a valid reset token."""
    # Phase 5: Validate token and reset password
    return SuccessResponse(message="Password reset successful")


@router.post(
    "/verify-email",
    response_model=SuccessResponse[None],
    summary="Verify email",
    description="Verify email address using token.",
)
async def verify_email(
    body: VerifyEmailRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[None]:
    """Verify email with a valid verification token."""
    # Phase 5: Validate token and mark email verified
    return SuccessResponse(message="Email verified successfully")


@router.post(
    "/resend-verification",
    response_model=SuccessResponse[None],
    summary="Resend verification email",
    description="Resend email verification link.",
)
async def resend_verification(
    body: ResendVerificationRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse[None]:
    """Resend email verification link."""
    # Phase 5: Resend verification email
    return SuccessResponse(
        message="If the email exists, a verification link has been sent."
    )
