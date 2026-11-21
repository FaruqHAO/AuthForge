"""Seed default roles, permissions, and initial admin account.

This script is idempotent — it checks for existing records before inserting.
Run after database migrations:

    python -m scripts.seed_roles_permissions

Security notes:
- Admin password comes from ADMIN_PASSWORD environment variable
- Never hardcode passwords in seed scripts
- This script is for initial setup only, not for production re-seeding
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import Base, get_engine, get_session_factory, init_db
from app.core.security import hash_password

from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.association import UserRole, RolePermission

logger = logging.getLogger(__name__)

# ── Default Data ──────────────────────────────────────────────────────────

DEFAULT_PERMISSIONS = [
    # User management
    {"name": "users.read", "description": "Read user information", "resource": "users", "action": "read"},
    {"name": "users.create", "description": "Create new users", "resource": "users", "action": "create"},
    {"name": "users.update", "description": "Update user information", "resource": "users", "action": "update"},
    {"name": "users.delete", "description": "Delete users", "resource": "users", "action": "delete"},
    # Ticket management
    {"name": "tickets.read", "description": "Read tickets", "resource": "tickets", "action": "read"},
    {"name": "tickets.create", "description": "Create tickets", "resource": "tickets", "action": "create"},
    {"name": "tickets.update", "description": "Update tickets", "resource": "tickets", "action": "update"},
    {"name": "tickets.delete", "description": "Delete tickets", "resource": "tickets", "action": "delete"},
    # Reports
    {"name": "reports.read", "description": "Read reports", "resource": "reports", "action": "read"},
    # System
    {"name": "system.manage", "description": "Manage system settings", "resource": "system", "action": "manage"},
]

DEFAULT_ROLES = [
    {
        "name": "ADMIN",
        "description": "Full system administrator",
        "is_default": False,
        "permissions": [
            "users.read", "users.create", "users.update", "users.delete",
            "tickets.read", "tickets.create", "tickets.update", "tickets.delete",
            "reports.read",
            "system.manage",
        ],
    },
    {
        "name": "MANAGER",
        "description": "Team manager with elevated permissions",
        "is_default": False,
        "permissions": [
            "users.read",
            "tickets.read", "tickets.create", "tickets.update", "tickets.delete",
            "reports.read",
        ],
    },
    {
        "name": "SUPPORT",
        "description": "Support staff with limited permissions",
        "is_default": False,
        "permissions": [
            "users.read",
            "tickets.read", "tickets.create", "tickets.update",
        ],
    },
    {
        "name": "USER",
        "description": "Default user with basic permissions",
        "is_default": True,
        "permissions": [
            "tickets.read", "tickets.create",
        ],
    },
]


async def seed_permissions(session) -> dict[str, int]:
    """Create default permissions if they don't exist.

    Returns a mapping of permission name -> permission ID.
    """
    permission_map: dict[str, int] = {}

    for perm_data in DEFAULT_PERMISSIONS:
        # Check if permission already exists
        result = await session.execute(
            select(Permission).where(Permission.name == perm_data["name"])
        )
        existing = result.scalar_one_or_none()

        if existing:
            permission_map[perm_data["name"]] = existing.id
            logger.info("Permission '%s' already exists (id=%s)", perm_data["name"], existing.id)
        else:
            permission = Permission(**perm_data)
            session.add(permission)
            await session.flush()
            permission_map[perm_data["name"]] = permission.id
            logger.info("Created permission '%s' (id=%s)", perm_data["name"], permission.id)

    return permission_map


async def seed_roles(session, permission_map: dict[str, int]) -> None:
    """Create default roles with their permissions if they don't exist."""
    for role_data in DEFAULT_ROLES:
        result = await session.execute(
            select(Role).where(Role.name == role_data["name"])
        )
        existing = result.scalar_one_or_none()

        if existing:
            logger.info("Role '%s' already exists (id=%d)", role_data["name"], existing.id)
            role = existing
        else:
            role = Role(
                name=role_data["name"],
                description=role_data["description"],
                is_default=role_data["is_default"],
            )
            session.add(role)
            await session.flush()
            logger.info("Created role '%s' (id=%s)", role_data["name"], role.id)

        # Assign permissions to role
        for perm_name in role_data["permissions"]:
            perm_id = permission_map.get(perm_name)
            if perm_id is None:
                logger.warning("Permission '%s' not found, skipping", perm_name)
                continue

            # Check if already assigned
            result = await session.execute(
                select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == perm_id,
                )
            )
            if result.scalar_one_or_none() is None:
                rp = RolePermission(role_id=role.id, permission_id=perm_id)
                session.add(rp)
                logger.info("Assigned permission '%s' to role '%s'", perm_name, role_data["name"])


async def seed_admin_user(session) -> None:
    """Create initial admin user from environment variables.

    Password is read from ADMIN_PASSWORD env var — never hardcoded.
    """
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    admin_password = os.environ.get("ADMIN_PASSWORD")

    if not admin_password:
        logger.warning(
            "ADMIN_PASSWORD not set. Skipping admin user creation. "
            "Set ADMIN_PASSWORD environment variable and re-run."
        )
        return

    result = await session.execute(
        select(User).where(User.email == admin_email)
    )
    if result.scalar_one_or_none():
        logger.info("Admin user '%s' already exists", admin_email)
        return

    # Get ADMIN role
    result = await session.execute(
        select(Role).where(Role.name == "ADMIN")
    )
    admin_role = result.scalar_one_or_none()
    if not admin_role:
        logger.error("ADMIN role not found. Seed roles first.")
        return

    admin_user = User(
        email=admin_email,
        password_hash=hash_password(admin_password),
        first_name="Admin",
        last_name="User",
        is_active=True,
        is_verified=True,  # Admin accounts are pre-verified
    )
    session.add(admin_user)
    await session.flush()

    # Assign ADMIN role
    ur = UserRole(user_id=admin_user.id, role_id=admin_role.id)
    session.add(ur)

    logger.info("Created admin user '%s' (id=%s)", admin_email, admin_user.id)


async def main() -> None:
    """Run the seed script."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logger.info("Starting seed...")

    await init_db()
    factory = get_session_factory()

    async with factory() as session:
        async with session.begin():
            permission_map = await seed_permissions(session)
            await seed_roles(session, permission_map)
            await seed_admin_user(session)

    logger.info("Seed completed successfully")


if __name__ == "__main__":
    asyncio.run(main())
