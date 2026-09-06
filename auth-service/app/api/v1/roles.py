"""Admin role management routes.

Endpoints:
- GET    /admin/roles — List all roles
- POST   /admin/roles — Create a new role
- PUT    /admin/roles/{role_id} — Update role
- DELETE /admin/roles/{role_id} — Delete role
- POST   /admin/roles/{role_id}/permissions — Assign permission to role
- DELETE /admin/roles/{role_id}/permissions/{permission_id} — Remove permission

All endpoints require ADMIN role.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.core.exceptions import RoleNotFoundError, PermissionNotFoundError
from app.api.schemas import SuccessResponse
from app.api.v1.deps import require_role
from app.repositories.role_repository import RoleRepository
from app.models.role import Role

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────


class RoleResponse(BaseModel):
    """Role response schema."""
    id: uuid.UUID
    name: str
    description: str | None
    is_default: bool

    model_config = {"from_attributes": True}


class CreateRoleRequest(BaseModel):
    """Create role request."""
    name: str = Field(..., min_length=1, max_length=50)
    description: str | None = None
    is_default: bool = False


class AssignPermissionRequest(BaseModel):
    """Assign permission to role request."""
    permission_id: uuid.UUID


# ── Routes ───────────────────────────────────────────────────────────────


@router.get(
    "",
    response_model=SuccessResponse[list[RoleResponse]],
    summary="List roles",
    description="Get all roles. Requires ADMIN role.",
)
async def list_roles(
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[list[RoleResponse]]:
    """List all roles. ADMIN only."""
    role_repo = RoleRepository(db)
    roles = await role_repo.list_roles()
    return SuccessResponse(
        data=[RoleResponse.model_validate(r) for r in roles],
        message=f"Found {len(roles)} roles",
    )


@router.post(
    "",
    response_model=SuccessResponse[RoleResponse],
    status_code=201,
    summary="Create role",
    description="Create a new role. Requires ADMIN role.",
)
async def create_role(
    body: CreateRoleRequest,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[RoleResponse]:
    """Create a new role. ADMIN only."""
    role_repo = RoleRepository(db)
    role = await role_repo.create_role(
        name=body.name,
        description=body.description,
        is_default=body.is_default,
    )
    return SuccessResponse(
        data=RoleResponse.model_validate(role),
        message="Role created successfully",
    )


@router.put(
    "/{role_id}",
    response_model=SuccessResponse[RoleResponse],
    summary="Update role",
    description="Update role details. Requires ADMIN role.",
)
async def update_role(
    role_id: uuid.UUID,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
    name: str | None = None,
    description: str | None = None,
    is_default: bool | None = None,
) -> SuccessResponse[RoleResponse]:
    """Update role details. ADMIN only."""
    role_repo = RoleRepository(db)
    role = await role_repo.get_role_by_id(role_id)
    if role is None:
        raise RoleNotFoundError()

    if name is not None:
        role.name = name.upper()
    if description is not None:
        role.description = description
    if is_default is not None:
        role.is_default = is_default

    await db.flush()
    return SuccessResponse(
        data=RoleResponse.model_validate(role),
        message="Role updated successfully",
    )


@router.delete(
    "/{role_id}",
    response_model=SuccessResponse[None],
    summary="Delete role",
    description="Delete a role. Requires ADMIN role.",
)
async def delete_role(
    role_id: uuid.UUID,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[None]:
    """Delete a role. ADMIN only."""
    role_repo = RoleRepository(db)
    deleted = await role_repo.delete_role(role_id)
    if not deleted:
        raise RoleNotFoundError()
    return SuccessResponse(message="Role deleted successfully")


@router.post(
    "/{role_id}/permissions",
    response_model=SuccessResponse[None],
    status_code=201,
    summary="Assign permission to role",
    description="Assign a permission to a role. Requires ADMIN role.",
)
async def assign_permission(
    role_id: uuid.UUID,
    body: AssignPermissionRequest,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[None]:
    """Assign a permission to a role. ADMIN only."""
    role_repo = RoleRepository(db)

    # Verify role exists
    role = await role_repo.get_role_by_id(role_id)
    if role is None:
        raise RoleNotFoundError()

    # Verify permission exists
    permission = await role_repo.get_permission_by_id(body.permission_id)
    if permission is None:
        raise PermissionNotFoundError()

    await role_repo.assign_permission_to_role(role_id, body.permission_id)
    return SuccessResponse(message="Permission assigned to role")


@router.delete(
    "/{role_id}/permissions/{permission_id}",
    response_model=SuccessResponse[None],
    summary="Remove permission from role",
    description="Remove a permission from a role. Requires ADMIN role.",
)
async def remove_permission(
    role_id: uuid.UUID,
    permission_id: uuid.UUID,
    payload: Annotated[dict, Depends(require_role("ADMIN"))],
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[None]:
    """Remove a permission from a role. ADMIN only."""
    role_repo = RoleRepository(db)
    removed = await role_repo.remove_permission_from_role(role_id, permission_id)
    if not removed:
        raise PermissionNotFoundError()
    return SuccessResponse(message="Permission removed from role")
