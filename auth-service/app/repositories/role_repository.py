"""Role and Permission repository.

Data access layer for Role, Permission, UserRole, and RolePermission.
Encapsulates all RBAC-related database queries.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.role import Role
from app.models.permission import Permission
from app.models.association import UserRole, RolePermission


class RoleRepository:
    """Data access for Role and Permission entities."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_role_by_id(self, role_id: uuid.UUID) -> Role | None:
        """Get role by UUID."""
        result = await self.session.execute(
            select(Role).where(Role.id == role_id)
        )
        return result.scalar_one_or_none()

    async def get_role_by_name(self, name: str) -> Role | None:
        """Get role by name (case-insensitive)."""
        result = await self.session.execute(
            select(Role).where(Role.name == name.upper())
        )
        return result.scalar_one_or_none()

    async def get_default_roles(self) -> list[Role]:
        """Get all roles marked as default."""
        result = await self.session.execute(
            select(Role).where(Role.is_default == True)  # noqa: E712
        )
        return list(result.scalars().all())

    async def create_role(
        self,
        name: str,
        description: str | None = None,
        is_default: bool = False,
    ) -> Role:
        """Create a new role."""
        role = Role(
            name=name.upper(),
            description=description,
            is_default=is_default,
        )
        self.session.add(role)
        await self.session.flush()
        return role

    async def list_roles(self) -> list[Role]:
        """List all roles."""
        result = await self.session.execute(
            select(Role).order_by(Role.name)
        )
        return list(result.scalars().all())

    async def delete_role(self, role_id: uuid.UUID) -> bool:
        """Delete a role by ID. Returns True if deleted."""
        role = await self.get_role_by_id(role_id)
        if role is None:
            return False
        await self.session.delete(role)
        await self.session.flush()
        return True

    # ── Permission Methods ───────────────────────────────────────────────

    async def get_permission_by_id(
        self, permission_id: uuid.UUID
    ) -> Permission | None:
        """Get permission by UUID."""
        result = await self.session.execute(
            select(Permission).where(Permission.id == permission_id)
        )
        return result.scalar_one_or_none()

    async def get_permission_by_name(
        self, name: str
    ) -> Permission | None:
        """Get permission by name."""
        result = await self.session.execute(
            select(Permission).where(Permission.name == name)
        )
        return result.scalar_one_or_none()

    async def create_permission(
        self,
        name: str,
        resource: str,
        action: str,
        description: str | None = None,
    ) -> Permission:
        """Create a new permission."""
        permission = Permission(
            name=name,
            resource=resource,
            action=action,
            description=description,
        )
        self.session.add(permission)
        await self.session.flush()
        return permission

    async def list_permissions(self) -> list[Permission]:
        """List all permissions."""
        result = await self.session.execute(
            select(Permission).order_by(Permission.resource, Permission.action)
        )
        return list(result.scalars().all())

    # ── Assignment Methods ───────────────────────────────────────────────

    async def assign_role_to_user(
        self,
        user_id: uuid.UUID,
        role_id: uuid.UUID,
        assigned_by: uuid.UUID | None = None,
    ) -> UserRole:
        """Assign a role to a user."""
        ur = UserRole(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by,
        )
        self.session.add(ur)
        await self.session.flush()
        return ur

    async def remove_role_from_user(
        self,
        user_id: uuid.UUID,
        role_id: uuid.UUID,
    ) -> bool:
        """Remove a role from a user. Returns True if removed."""
        result = await self.session.execute(
            select(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == role_id,
            )
        )
        ur = result.scalar_one_or_none()
        if ur is None:
            return False
        await self.session.delete(ur)
        await self.session.flush()
        return True

    async def assign_permission_to_role(
        self,
        role_id: uuid.UUID,
        permission_id: uuid.UUID,
        granted_by: uuid.UUID | None = None,
    ) -> RolePermission:
        """Assign a permission to a role."""
        rp = RolePermission(
            role_id=role_id,
            permission_id=permission_id,
            granted_by=granted_by,
        )
        self.session.add(rp)
        await self.session.flush()
        return rp

    async def remove_permission_from_role(
        self,
        role_id: uuid.UUID,
        permission_id: uuid.UUID,
    ) -> bool:
        """Remove a permission from a role. Returns True if removed."""
        result = await self.session.execute(
            select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id,
            )
        )
        rp = result.scalar_one_or_none()
        if rp is None:
            return False
        await self.session.delete(rp)
        await self.session.flush()
        return True

    async def get_user_permissions(self, user_id: uuid.UUID) -> list[str]:
        """Get all permission names for a user.

        Returns the union of permissions from all assigned roles.
        Uses a single query with joins for efficiency.
        """
        result = await self.session.execute(
            select(Permission.name)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .join(Role, Role.id == RolePermission.role_id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
            .distinct()
        )
        return [row[0] for row in result.all()]

    async def get_user_roles(self, user_id: uuid.UUID) -> list[Role]:
        """Get all roles assigned to a user."""
        result = await self.session.execute(
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
            .order_by(Role.name)
        )
        return list(result.scalars().all())
