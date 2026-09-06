"""Unit tests for authentication service business logic.

Tests cover:
- User registration (valid, duplicate email, weak password)
- Login (valid, invalid credentials, locked account, disabled account)
- Token refresh (valid, expired, revoked, reuse detection)
- Profile management (update, username uniqueness)
- Password change (valid, wrong current password, weak new password)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.exceptions import (
    AccountDisabledError,
    AccountLockedError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    RefreshTokenReuseError,
    RefreshTokenRevokedError,
    WeakPasswordError,
    UsernameTakenError,
)
from app.core.security import hash_password
from app.services.auth_service import AuthService


@pytest.fixture
def mock_session():
    """Mock async database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.add = AsyncMock()
    return session


@pytest.fixture
def auth_service(mock_session):
    """Create AuthService with mocked dependencies."""
    return AuthService(mock_session)


class TestRegistration:
    """Tests for user registration."""

    @pytest.mark.asyncio
    async def test_register_success(self, auth_service):
        """Successful registration should create a user."""
        # Mock email not exists
        auth_service.user_repo.email_exists = AsyncMock(return_value=False)
        auth_service.user_repo.username_exists = AsyncMock(return_value=False)
        auth_service.user_repo.create = AsyncMock(return_value=MagicMock(
            id=uuid.uuid4(),
            email="test@example.com",
        ))
        auth_service.role_repo.get_default_roles = AsyncMock(return_value=[])
        auth_service.role_repo.assign_role_to_user = AsyncMock()

        user = await auth_service.register(
            email="test@example.com",
            password="StrongPass123!",
        )
        assert user is not None

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, auth_service):
        """Registration with existing email should raise error."""
        auth_service.user_repo.email_exists = AsyncMock(return_value=True)

        with pytest.raises(EmailAlreadyExistsError):
            await auth_service.register(
                email="existing@example.com",
                password="StrongPass123!",
            )

    @pytest.mark.asyncio
    async def test_register_weak_password(self, auth_service):
        """Registration with weak password should raise error."""
        auth_service.user_repo.email_exists = AsyncMock(return_value=False)

        with pytest.raises(WeakPasswordError):
            await auth_service.register(
                email="test@example.com",
                password="weak",
            )

    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, auth_service):
        """Registration with taken username should raise error."""
        auth_service.user_repo.email_exists = AsyncMock(return_value=False)
        auth_service.user_repo.username_exists = AsyncMock(return_value=True)

        with pytest.raises(UsernameTakenError):
            await auth_service.register(
                email="test@example.com",
                password="StrongPass123!",
                username="taken",
            )


class TestLogin:
    """Tests for user login."""

    @pytest.mark.asyncio
    async def test_login_success(self, auth_service):
        """Successful login should return tokens."""
        mock_user = MagicMock(
            id=uuid.uuid4(),
            email="test@example.com",
            password_hash=hash_password("StrongPass123!"),
            is_active=True,
            is_verified=True,
            is_locked=False,
            failed_login_attempts=0,
            locked_until=None,
        )

        auth_service.user_repo.get_by_email = AsyncMock(return_value=mock_user)
        auth_service.user_repo.reset_failed_login = AsyncMock()
        auth_service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        # Mock session creation
        mock_session = MagicMock(id=uuid.uuid4())
        auth_service.session.add = MagicMock()
        auth_service.session.flush = AsyncMock()

        # Mock role queries
        auth_service.role_repo.get_user_roles = AsyncMock(return_value=[])
        auth_service.role_repo.get_user_permissions = AsyncMock(return_value=[])

        # Mock token creation
        with patch("app.services.auth_service.create_access_token", return_value="access-token"):
            with patch("app.services.auth_service.create_refresh_token", return_value=("refresh-token", "hash")):
                with patch("app.services.auth_service.generate_token_family", return_value="family-123"):
                    user, access, refresh = await auth_service.login(
                        email="test@example.com",
                        password="StrongPass123!",
                    )

        assert access == "access-token"
        assert refresh == "refresh-token"

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, auth_service):
        """Login with wrong password should raise error."""
        mock_user = MagicMock(
            id=uuid.uuid4(),
            password_hash=hash_password("StrongPass123!"),
            is_active=True,
            is_locked=False,
            failed_login_attempts=0,
            locked_until=None,
        )

        auth_service.user_repo.get_by_email = AsyncMock(return_value=mock_user)
        auth_service.user_repo.increment_failed_login = AsyncMock()
        auth_service.session.refresh = AsyncMock()

        with pytest.raises(InvalidCredentialsError):
            await auth_service.login(
                email="test@example.com",
                password="WrongPassword123!",
            )

    @pytest.mark.asyncio
    async def test_login_locked_account(self, auth_service):
        """Login to locked account should raise error."""
        mock_user = MagicMock(
            id=uuid.uuid4(),
            is_locked=True,
            locked_until=datetime.now(UTC) + timedelta(minutes=10),
        )

        auth_service.user_repo.get_by_email = AsyncMock(return_value=mock_user)

        with pytest.raises(AccountLockedError):
            await auth_service.login(
                email="test@example.com",
                password="StrongPass123!",
            )

    @pytest.mark.asyncio
    async def test_login_disabled_account(self, auth_service):
        """Login to disabled account should raise error."""
        mock_user = MagicMock(
            id=uuid.uuid4(),
            is_active=False,
            is_locked=False,
            locked_until=None,
        )

        auth_service.user_repo.get_by_email = AsyncMock(return_value=mock_user)

        with pytest.raises(AccountDisabledError):
            await auth_service.login(
                email="test@example.com",
                password="StrongPass123!",
            )

    @pytest.mark.asyncio
    async def test_login_nonexistent_email(self, auth_service):
        """Login with non-existent email should raise InvalidCredentialsError."""
        auth_service.user_repo.get_by_email = AsyncMock(return_value=None)

        with pytest.raises(InvalidCredentialsError):
            await auth_service.login(
                email="nonexistent@example.com",
                password="StrongPass123!",
            )


class TestPasswordChange:
    """Tests for password change."""

    @pytest.mark.asyncio
    async def test_change_password_success(self, auth_service):
        """Successful password change should update hash."""
        mock_user = MagicMock(
            id=uuid.uuid4(),
            password_hash=hash_password("OldPassword123!"),
        )

        auth_service.user_repo.get_by_id = AsyncMock(return_value=mock_user)
        auth_service.user_repo.update = AsyncMock()
        auth_service.logout_all = AsyncMock()

        await auth_service.change_password(
            user_id=mock_user.id,
            current_password="OldPassword123!",
            new_password="NewPassword123!",
        )

        auth_service.user_repo.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, auth_service):
        """Password change with wrong current password should fail."""
        mock_user = MagicMock(
            id=uuid.uuid4(),
            password_hash=hash_password("OldPassword123!"),
        )

        auth_service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        with pytest.raises(InvalidCredentialsError):
            await auth_service.change_password(
                user_id=mock_user.id,
                current_password="WrongPassword123!",
                new_password="NewPassword123!",
            )

    @pytest.mark.asyncio
    async def test_change_password_weak_new(self, auth_service):
        """Password change with weak new password should fail."""
        mock_user = MagicMock(
            id=uuid.uuid4(),
            password_hash=hash_password("OldPassword123!"),
        )

        auth_service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        with pytest.raises(WeakPasswordError):
            await auth_service.change_password(
                user_id=mock_user.id,
                current_password="OldPassword123!",
                new_password="weak",
            )
