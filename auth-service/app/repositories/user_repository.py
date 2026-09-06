"""User repository.

Data access layer for User entities. Encapsulates all database
queries related to users, keeping business logic in services.

Design decisions:
- All methods accept an AsyncSession (dependency injected)
- Methods return domain objects, not raw rows
- Query builders are composable for complex lookups
- No business logic in repositories — just data access
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.user import User
from app.models.association import UserRole


class UserRepository:
    """Data access for User entities."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Get user by UUID."""
        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """Get user by email address (case-insensitive)."""
        result = await self.session.execute(
            select(User).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> User | None:
        """Get user by username."""
        result = await self.session.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()

    async def create(self, **kwargs: object) -> User:
        """Create a new user.

        All keyword arguments are passed directly to the User constructor.
        The session is flushed to generate the ID but not committed
        (commit is handled by the service layer or session context).
        """
        user = User(**kwargs)  # type: ignore[arg-type]
        self.session.add(user)
        await self.session.flush()
        return user

    async def update(self, user_id: uuid.UUID, **kwargs: object) -> User | None:
        """Update user fields by ID."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(**kwargs)
        )
        await self.session.flush()
        return await self.get_by_id(user_id)

    async def email_exists(self, email: str) -> bool:
        """Check if an email is already registered."""
        result = await self.session.execute(
            select(User.id).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none() is not None

    async def username_exists(self, username: str) -> bool:
        """Check if a username is already taken."""
        result = await self.session.execute(
            select(User.id).where(User.username == username)
        )
        return result.scalar_one_or_none() is not None

    async def increment_failed_login(self, user_id: uuid.UUID) -> None:
        """Increment the failed login attempt counter."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_attempts=User.failed_login_attempts + 1,
            )
        )
        await self.session.flush()

    async def reset_failed_login(self, user_id: uuid.UUID) -> None:
        """Reset failed login attempts after successful login."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_attempts=0,
                is_locked=False,
                locked_until=None,
                last_login_at=datetime.now(UTC),
            )
        )
        await self.session.flush()

    async def lock_account(self, user_id: uuid.UUID, until: datetime) -> None:
        """Lock the user account until the specified time."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                is_locked=True,
                locked_until=until,
            )
        )
        await self.session.flush()

    async def list_users(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        is_active: bool | None = None,
    ) -> tuple[list[User], int]:
        """List users with pagination.

        Returns:
            Tuple of (list of users, total count)
        """
        query = select(User)
        count_query = select(User.id)

        if is_active is not None:
            query = query.where(User.is_active == is_active)
            count_query = count_query.where(User.is_active == is_active)

        # Get total count
        count_result = await self.session.execute(count_query)
        total = len(count_result.all())

        # Get paginated results
        query = query.offset(offset).limit(limit).order_by(User.created_at.desc())
        result = await self.session.execute(query)
        users = list(result.scalars().all())

        return users, total
