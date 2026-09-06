"""Admin user management routes.

Endpoints:
- GET  /admin/users — List users (paginated)
- GET  /admin/users/{user_id} — Get user details
- PUT  /admin/users/{user_id} — Update user
- POST /admin/users/{user_id}/activate — Activate user
- DELETE /admin/users/{user_id} — Deactivate user

All endpoints require ADMIN role.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.core.exceptions import UserNotFoundError
from app.api.schemas import SuccessResponse, PaginatedResponse
from app.api.v1.deps import require_role, get_user_id_from_payload
from app.schemas.auth import UserProfile
from app.repositories.user_repository import UserRepository

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[UserProfile],
    summary="List users",
    description="Get a paginated list of users. Requires ADMIN role.",
)
async def list_users(
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    is_active: bool | None = Query(default=None, description="Filter by active status"),
) -> PaginatedResponse[UserProfile]:
    """List users with pagination. ADMIN only."""
    user_repo = UserRepository(db)
    offset = (page - 1) * page_size
    users, total = await user_repo.list_users(
        offset=offset,
        limit=page_size,
        is_active=is_active,
    )

    return PaginatedResponse(
        data=[UserProfile.model_validate(u) for u in users],
        total=total,
        page=page,
        page_size=page_size,
        message=f"Found {total} users",
    )


@router.get(
    "/{user_id}",
    response_model=SuccessResponse[UserProfile],
    summary="Get user",
    description="Get user details by ID. Requires ADMIN role.",
)
async def get_user(
    user_id: uuid.UUID,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[UserProfile]:
    """Get user details. ADMIN only."""
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id)
    if user is None:
        raise UserNotFoundError()

    return SuccessResponse(
        data=UserProfile.model_validate(user),
        message="User retrieved successfully",
    )


@router.put(
    "/{user_id}",
    response_model=SuccessResponse[UserProfile],
    summary="Update user",
    description="Update user details. Requires ADMIN role.",
)
async def update_user(
    user_id: uuid.UUID,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
    first_name: str | None = None,
    last_name: str | None = None,
    is_active: bool | None = None,
    is_verified: bool | None = None,
) -> SuccessResponse[UserProfile]:
    """Update user details. ADMIN only."""
    user_repo = UserRepository(db)

    updates: dict[str, object] = {}
    if first_name is not None:
        updates["first_name"] = first_name
    if last_name is not None:
        updates["last_name"] = last_name
    if is_active is not None:
        updates["is_active"] = is_active
    if is_verified is not None:
        updates["is_verified"] = is_verified

    user = await user_repo.update(user_id, **updates)
    if user is None:
        raise UserNotFoundError()

    return SuccessResponse(
        data=UserProfile.model_validate(user),
        message="User updated successfully",
    )


@router.post(
    "/{user_id}/activate",
    response_model=SuccessResponse[UserProfile],
    summary="Activate user",
    description="Activate a deactivated user account. Requires ADMIN role.",
)
async def activate_user(
    user_id: uuid.UUID,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[UserProfile]:
    """Activate a user account. ADMIN only."""
    user_repo = UserRepository(db)
    user = await user_repo.update(user_id, is_active=True, is_locked=False)
    if user is None:
        raise UserNotFoundError()

    return SuccessResponse(
        data=UserProfile.model_validate(user),
        message="User activated successfully",
    )


@router.delete(
    "/{user_id}",
    response_model=SuccessResponse[None],
    summary="Deactivate user",
    description="Deactivate a user account. Requires ADMIN role.",
)
async def deactivate_user(
    user_id: uuid.UUID,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[None]:
    """Deactivate a user account. ADMIN only."""
    user_repo = UserRepository(db)
    user = await user_repo.update(user_id, is_active=False)
    if user is None:
        raise UserNotFoundError()

    return SuccessResponse(message="User deactivated successfully")
