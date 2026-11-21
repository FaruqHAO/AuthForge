"""Reusable authorization dependencies.

Provides FastAPI dependency functions for authorization:
- require_authenticated_user() — Ensures user is logged in
- require_role("ADMIN") — Ensures user has a specific role
- require_permission("users.delete") — Ensures user has a specific permission

Usage in route handlers:

    @router.delete("/users/{user_id}")
    async def delete_user(
        user_id: uuid.UUID,
        current_user = Depends(require_permission("users.delete")),
    ):
        ...

Design decisions:
- Authorization is centralized here, not scattered across handlers
- Permissions are checked from JWT claims (not database) for performance
- Roles are checked from JWT claims (not database) for performance
- If a user's permissions change, they need to re-login to get updated claims
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, Header, Cookie

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    InvalidTokenError,
    InsufficientPermissionsError,
    PermissionDeniedError,
)
from app.core.security import decode_access_token
from app.schemas.auth import UserProfile


async def get_current_user_payload(
    authorization: str | None = Header(default=None),
    access_token_cookie: str | None = Cookie(default=None, alias="access_token"),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Extract and validate the current user's JWT claims.

    Supports both Bearer token and cookie authentication.
    Returns the full JWT payload (claims dict).
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
    return payload


async def require_authenticated_user(
    payload: dict = Depends(get_current_user_payload),
) -> dict:
    """Dependency that ensures the user is authenticated.

    Returns the JWT payload with user_id and claims.
    Raises InvalidTokenError if no valid token is provided.
    """
    return payload


def require_role(required_role: str):
    """Build an async dependency that checks the authenticated user's role."""
    async def check_role(payload: dict = Depends(get_current_user_payload)) -> dict:
        if required_role not in payload.get("roles", []):
            raise InsufficientPermissionsError(
                message=f"Role '{required_role}' required"
            )
        return payload

    return check_role


def require_permission(required_permission: str):
    """Build an async dependency that checks the required permission."""
    async def check_permission(payload: dict = Depends(get_current_user_payload)) -> dict:
        if required_permission not in payload.get("permissions", []):
            raise PermissionDeniedError(
                message=f"Permission '{required_permission}' required"
            )
        return payload

    return check_permission


def get_user_id_from_payload(payload: dict) -> uuid.UUID:
    """Extract user UUID from JWT payload."""
    user_id = payload.get("sub")
    if user_id is None:
        raise InvalidTokenError(message="Token missing user ID")
    try:
        return uuid.UUID(user_id)
    except ValueError:
        raise InvalidTokenError(message="Invalid user ID in token")


# ── Type aliases for route signatures ────────────────────────────────────

CurrentUser = Annotated[dict, Depends(require_authenticated_user)]
