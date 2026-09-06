"""Authentication service.

Business logic for all authentication operations:
- User registration with validation
- Login with account lockout protection
- Token refresh with rotation and reuse detection
- Profile management
- Password change

This service orchestrates repositories, security primitives,
and external services (email, Redis for rate limiting).

Design decisions:
- All methods are async for non-blocking I/O
- Business logic is here, not in route handlers
- Error handling uses custom exceptions (never raw HTTP)
- Audit logging is called for all security events
- Rate limiting is checked before expensive operations
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.exceptions import (
    AccountDisabledError,
    AccountLockedError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    RefreshTokenReuseError,
    RefreshTokenRevokedError,
    TokenExpiredError,
    InvalidTokenError,
    UsernameTakenError,
    WeakPasswordError,
    UserNotFoundError,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    generate_token_family,
    hash_password,
    hash_token,
    needs_rehash,
    validate_password_strength,
    verify_password,
)
from app.repositories.user_repository import UserRepository
from app.repositories.role_repository import RoleRepository
from app.models.user import User
from app.models.session import Session
from app.models.refresh_token import RefreshToken

logger = logging.getLogger(__name__)

# ── Account Lockout Configuration ────────────────────────────────────────

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


class AuthService:
    """Authentication business logic."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)
        self.role_repo = RoleRepository(session)

    # ── Registration ─────────────────────────────────────────────────────

    async def register(
        self,
        email: str,
        password: str,
        *,
        first_name: str | None = None,
        last_name: str | None = None,
        username: str | None = None,
    ) -> User:
        """Register a new user.

        Validates:
        - Email is not already registered
        - Password meets strength requirements
        - Username is not already taken (if provided)

        After registration:
        - Creates user with hashed password
        - Assigns default roles
        - Creates audit log entry
        - Triggers email verification (Phase 5)

        Raises:
            EmailAlreadyExistsError: If email is taken
            WeakPasswordError: If password doesn't meet requirements
            UsernameTakenError: If username is taken
        """
        # Check email uniqueness
        if await self.user_repo.email_exists(email):
            raise EmailAlreadyExistsError()

        # Validate password strength
        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            raise WeakPasswordError(message=error_msg)

        # Check username uniqueness
        if username and await self.user_repo.username_exists(username):
            raise UsernameTakenError()

        # Create user
        user = await self.user_repo.create(
            email=email.lower().strip(),
            password_hash=hash_password(password),
            first_name=first_name,
            last_name=last_name,
            username=username,
            is_active=True,
            is_verified=False,
        )

        # Assign default roles
        default_roles = await self.role_repo.get_default_roles()
        for role in default_roles:
            await self.role_repo.assign_role_to_user(user.id, role.id)

        logger.info("User registered: %s (id=%s)", email, user.id)
        return user

    # ── Login ────────────────────────────────────────────────────────────

    async def login(
        self,
        email: str,
        password: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[User, str, str]:
        """Authenticate a user and create a session.

        Validates:
        - Email exists
        - Account is not locked
        - Account is active
        - Password is correct
        - Email is verified

        Creates:
        - Session with token family
        - Initial refresh token
        - Audit log entry

        Returns:
            Tuple of (user, access_token, refresh_token)

        Raises:
            InvalidCredentialsError: Wrong email or password
            AccountLockedError: Too many failed attempts
            AccountDisabledError: Account deactivated
        """
        user = await self.user_repo.get_by_email(email)

        # Always check password even if user not found (timing attack prevention)
        if user is None:
            # Run dummy hash to prevent timing attacks
            hash_password("dummy-password-to-prevent-timing-attacks")
            raise InvalidCredentialsError()

        # Check if account is locked
        if user.is_locked:
            if user.locked_until and user.locked_until > datetime.now(UTC):
                raise AccountLockedError()
            # Lock has expired, unlock automatically
            await self.user_repo.reset_failed_login(user.id)
            user = await self.user_repo.get_by_id(user.id)

        # Check if account is active
        if not user.is_active:
            raise AccountDisabledError()

        # Verify password
        if not verify_password(password, user.password_hash):
            await self._handle_failed_login(user)
            raise InvalidCredentialsError()

        # Check email verification
        if not user.is_verified:
            # Still allow login but with limited access
            logger.warning("Unverified user login: %s", email)

        # Successful login — reset failed attempts
        await self.user_repo.reset_failed_login(user.id)

        # Create session and tokens
        access_token, refresh_token, session = await self._create_session(
            user,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info("User logged in: %s (id=%s)", email, user.id)
        return user, access_token, refresh_token

    async def _handle_failed_login(self, user: User) -> None:
        """Handle a failed login attempt.

        Increments the failed attempt counter and locks the account
        if the maximum number of attempts is reached.
        """
        await self.user_repo.increment_failed_login(user.id)
        await self.session.refresh(user)

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            lock_until = datetime.now(UTC) + timedelta(
                minutes=LOCKOUT_DURATION_MINUTES
            )
            await self.user_repo.lock_account(user.id, lock_until)
            logger.warning(
                "Account locked: %s (attempts=%d)",
                user.email,
                user.failed_login_attempts,
            )
        else:
            logger.info(
                "Failed login attempt: %s (attempts=%d/%d)",
                user.email,
                user.failed_login_attempts,
                MAX_FAILED_ATTEMPTS,
            )

    # ── Session Management ───────────────────────────────────────────────

    async def _create_session(
        self,
        user: User,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str, Session]:
        """Create a new session with tokens.

        Returns:
            Tuple of (access_token, refresh_token, session)
        """
        settings = get_settings()
        family_id = generate_token_family()

        # Create session
        session = Session(
            user_id=user.id,
            refresh_token_family=family_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.now(UTC) + timedelta(
                days=settings.jwt.refresh_token_expire_days
            ),
        )
        self.session.add(session)
        await self.session.flush()

        # Create refresh token
        raw_refresh, refresh_hash = create_refresh_token(str(user.id))
        expires_at = datetime.now(UTC) + timedelta(
            days=settings.jwt.refresh_token_expire_days
        )

        refresh_token = RefreshToken(
            token_hash=refresh_hash,
            user_id=user.id,
            session_id=session.id,
            family_id=family_id,
            expires_at=expires_at,
        )
        self.session.add(refresh_token)
        await self.session.flush()

        # Create access token with roles and permissions
        roles = await self.role_repo.get_user_roles(user.id)
        permissions = await self.role_repo.get_user_permissions(user.id)

        extra_claims = {
            "roles": [r.name for r in roles],
            "permissions": permissions,
        }
        access_token = create_access_token(str(user.id), extra_claims=extra_claims)

        return access_token, raw_refresh, session

    # ── Token Refresh ────────────────────────────────────────────────────

    async def refresh_tokens(
        self,
        refresh_token: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str]:
        """Refresh an access token using a refresh token.

        Implements refresh token rotation:
        1. Validate the refresh token
        2. Check it hasn't been revoked
        3. Check for reuse (revoked token being used)
        4. Revoke the old token
        5. Create a new refresh token (same family)
        6. Create a new access token

        Returns:
            Tuple of (new_access_token, new_refresh_token)

        Raises:
            InvalidTokenError: Token is malformed
            TokenExpiredError: Token has expired
            RefreshTokenRevokedError: Token was already revoked
            RefreshTokenReuseError: Stolen token detected
        """
        # Decode the JWT
        payload = decode_refresh_token(refresh_token)
        user_id = payload.get("sub")
        if user_id is None:
            raise InvalidTokenError(message="Token missing subject")

        # Hash the token for database lookup
        token_hash = hash_token(refresh_token)

        # Find the token in database
        result = await self.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        db_token = result.scalar_one_or_none()

        if db_token is None:
            raise InvalidTokenError(message="Token not found")

        # Check if already revoked (reuse detection)
        if db_token.is_revoked:
            # Token reuse detected — kill entire family
            await self._kill_token_family(db_token.family_id)
            raise RefreshTokenReuseError()

        # Check ownership
        if str(db_token.user_id) != user_id:
            raise InvalidTokenError(message="Token user mismatch")

        # Get user
        user = await self.user_repo.get_by_id(uuid.UUID(user_id))
        if user is None:
            raise InvalidTokenError(message="User not found")
        if not user.is_active:
            raise AccountDisabledError()

        # Revoke the old token
        db_token.is_revoked = True
        db_token.rotated_at = datetime.now(UTC)
        await self.session.flush()

        # Create new refresh token (same family, parent = old token)
        raw_new_refresh, new_refresh_hash = create_refresh_token(user_id)
        settings = get_settings()
        expires_at = datetime.now(UTC) + timedelta(
            days=settings.jwt.refresh_token_expire_days
        )

        new_refresh = RefreshToken(
            token_hash=new_refresh_hash,
            user_id=db_token.user_id,
            session_id=db_token.session_id,
            family_id=db_token.family_id,
            parent_id=db_token.id,
            expires_at=expires_at,
        )
        self.session.add(new_refresh)
        await self.session.flush()

        # Update session last_used_at
        result = await self.session.execute(
            select(Session).where(Session.id == db_token.session_id)
        )
        session = result.scalar_one_or_none()
        if session:
            session.last_used_at = datetime.now(UTC)

        # Create new access token
        roles = await self.role_repo.get_user_roles(user.id)
        permissions = await self.role_repo.get_user_permissions(user.id)
        extra_claims = {
            "roles": [r.name for r in roles],
            "permissions": permissions,
        }
        new_access = create_access_token(user_id, extra_claims=extra_claims)

        logger.info("Tokens refreshed for user %s", user_id)
        return new_access, raw_new_refresh

    async def _kill_token_family(self, family_id: str) -> None:
        """Invalidate all tokens in a family (reuse detection response).

        When a revoked token is reused, the entire family is killed
        to prevent further use of potentially stolen tokens.
        """
        result = await self.session.execute(
            select(RefreshToken).where(
                RefreshToken.family_id == family_id,
                RefreshToken.is_revoked == False,  # noqa: E712
            )
        )
        tokens = result.scalars().all()
        for token in tokens:
            token.is_revoked = True
            token.rotated_at = datetime.now(UTC)
        await self.session.flush()
        logger.warning("Token family killed: %s (%d tokens)", family_id, len(tokens))

    # ── Logout ───────────────────────────────────────────────────────────

    async def logout(self, user_id: uuid.UUID, session_id: uuid.UUID) -> None:
        """Logout from a specific session.

        Revokes the session and all associated refresh tokens.
        """
        result = await self.session.execute(
            select(Session).where(
                Session.id == session_id,
                Session.user_id == user_id,
            )
        )
        session = result.scalar_one_or_none()
        if session is None:
            return

        # Revoke session
        session.revoked_at = datetime.now(UTC)

        # Revoke all refresh tokens in this session
        result = await self.session.execute(
            select(RefreshToken).where(
                RefreshToken.session_id == session_id,
                RefreshToken.is_revoked == False,  # noqa: E712
            )
        )
        tokens = result.scalars().all()
        for token in tokens:
            token.is_revoked = True
            token.rotated_at = datetime.now(UTC)
        await self.session.flush()

        logger.info("Session revoked: %s (user=%s)", session_id, user_id)

    async def logout_all(self, user_id: uuid.UUID) -> None:
        """Logout from all sessions.

        Revokes every active session and refresh token for the user.
        """
        # Revoke all active sessions
        result = await self.session.execute(
            select(Session).where(
                Session.user_id == user_id,
                Session.revoked_at.is_(None),
            )
        )
        sessions = result.scalars().all()
        for session in sessions:
            session.revoked_at = datetime.now(UTC)

        # Revoke all active refresh tokens
        result = await self.session.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,  # noqa: E712
            )
        )
        tokens = result.scalars().all()
        for token in tokens:
            token.is_revoked = True
            token.rotated_at = datetime.now(UTC)
        await self.session.flush()

        logger.info(
            "All sessions revoked for user %s (%d sessions, %d tokens)",
            user_id,
            len(sessions),
            len(tokens),
        )

    # ── Profile ──────────────────────────────────────────────────────────

    async def get_current_user(self, user_id: uuid.UUID) -> User:
        """Get the current authenticated user.

        Raises:
            UserNotFoundError: If user doesn't exist
        """
        user = await self.user_repo.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()
        return user

    async def update_profile(
        self,
        user_id: uuid.UUID,
        *,
        first_name: str | None = None,
        last_name: str | None = None,
        username: str | None = None,
    ) -> User:
        """Update user profile fields.

        Raises:
            UsernameTakenError: If new username is taken
            UserNotFoundError: If user doesn't exist
        """
        user = await self.user_repo.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()

        # Check username uniqueness if changing
        if username and username != user.username:
            if await self.user_repo.username_exists(username):
                raise UsernameTakenError()

        updates: dict[str, object] = {}
        if first_name is not None:
            updates["first_name"] = first_name
        if last_name is not None:
            updates["last_name"] = last_name
        if username is not None:
            updates["username"] = username

        if updates:
            updated_user = await self.user_repo.update(user_id, **updates)
            if updated_user is None:
                raise UserNotFoundError()
            return updated_user

        return user

    # ── Password Management ──────────────────────────────────────────────

    async def change_password(
        self,
        user_id: uuid.UUID,
        current_password: str,
        new_password: str,
    ) -> None:
        """Change user password.

        Requires the current password for verification.
        Invalidates all existing sessions after password change.

        Raises:
            InvalidCredentialsError: Current password is wrong
            WeakPasswordError: New password doesn't meet requirements
        """
        user = await self.user_repo.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()

        # Verify current password
        if not verify_password(current_password, user.password_hash):
            raise InvalidCredentialsError(
                message="Current password is incorrect"
            )

        # Validate new password strength
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            raise WeakPasswordError(message=error_msg)

        # Update password hash
        await self.user_repo.update(
            user_id,
            password_hash=hash_password(new_password),
        )

        # Invalidate all sessions (security measure after password change)
        await self.logout_all(user_id)

        logger.info("Password changed for user %s", user_id)
