"""Admin permission management routes.

Endpoints:
- GET  /admin/permissions — List all permissions
- POST /admin/permissions — Create a new permission

All endpoints require ADMIN role.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.api.schemas import SuccessResponse
from app.api.v1.deps import require_role
from app.repositories.role_repository import RoleRepository

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────


class PermissionResponse(BaseModel):
    """Permission response schema."""
    id: uuid.UUID
    name: str
    description: str | None
    resource: str
    action: str

    model_config = {"from_attributes": True}


class CreatePermissionRequest(BaseModel):
    """Create permission request."""
    name: str = Field(..., min_length=1, max_length=100, description="e.g., tickets.delete")
    resource: str = Field(..., min_length=1, max_length=50)
    action: str = Field(..., min_length=1, max_length=50)
    description: str | None = None


# ── Routes ───────────────────────────────────────────────────────────────


@router.get(
    "",
    response_model=SuccessResponse[list[PermissionResponse]],
    summary="List permissions",
    description="Get all permissions. Requires ADMIN role.",
)
async def list_permissions(
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[list[PermissionResponse]]:
    """List all permissions. ADMIN only."""
    role_repo = RoleRepository(db)
    permissions = await role_repo.list_permissions()
    return SuccessResponse(
        data=[PermissionResponse.model_validate(p) for p in permissions],
        message=f"Found {len(permissions)} permissions",
    )


@router.post(
    "",
    response_model=SuccessResponse[PermissionResponse],
    status_code=201,
    summary="Create permission",
    description="Create a new permission. Requires ADMIN role.",
)
async def create_permission(
    body: CreatePermissionRequest,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[PermissionResponse]:
    """Create a new permission. ADMIN only."""
    role_repo = RoleRepository(db)
    permission = await role_repo.create_permission(
        name=body.name,
        resource=body.resource,
        action=body.action,
        description=body.description,
    )
    return SuccessResponse(
        data=PermissionResponse.model_validate(permission),
        message="Permission created successfully",
    )
