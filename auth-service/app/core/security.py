"""Security foundation — password hashing, JWT, and refresh tokens.

This module is the cryptographic core of the auth service.
All security primitives are centralized here.

Password Hashing:
- Argon2id (OWASP-recommended, memory-hard)
- Parameters: time_cost=3, memory_cost=64MB, parallelism=4
- Never store plaintext passwords

JWT Tokens:
- Access tokens: 15 minutes, signed with HS256
- Contains: sub (user_id), jti (unique token ID), iss, aud, iat, exp
- Refresh tokens: 7 days, SHA-256 hashed before storage
- Token family tracking for rotation and reuse detection

Security considerations:
- All secrets come from environment variables (never hardcoded)
- Argon2id prevents GPU/ASIC attacks via memory hardness
- JWT expiration limits blast radius of token theft
- Refresh token hashing prevents database leaks from exposing tokens
- Token families enable detection of stolen refresh tokens
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import JWTError, jwt

from app.core.config import get_settings
from app.core.exceptions import (
    InvalidCredentialsError,
    TokenExpiredError,
    InvalidTokenError,
)

# ── Password Hashing ─────────────────────────────────────────────────────

# Argon2id parameters (OWASP recommended minimums)
_ARGON2_TIME_COST = 3        # Number of iterations
_ARGON2_MEMORY_COST = 65536  # 64 MB in KB
_ARGON2_PARALLELISM = 4      # Number of parallel threads
_ARGON2_HASH_LEN = 32        # Output hash length in bytes
_ARGON2_SALT_LEN = 16        # Salt length in bytes

# Password hashers — one for hashing, one for verification
# The hasher handles salt generation automatically
ph = PasswordHasher(
    time_cost=_ARGON2_TIME_COST,
    memory_cost=_ARGON2_MEMORY_COST,
    parallelism=_ARGON2_PARALLELISM,
    hash_len=_ARGON2_HASH_LEN,
    salt_len=_ARGON2_SALT_LEN,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id.

    The salt is generated automatically and embedded in the hash string.
    Each call produces a different hash for the same password.

    Returns:
        Argon2id hash string (e.g., $argon2id$v=19$m=65536,t=3,p=4$...)
    """
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against an Argon2id hash.

    Uses constant-time comparison internally (via argon2-cffi).
    Returns False on any exception (wrong password, malformed hash).

    Args:
        password: Plaintext password to verify
        password_hash: Stored Argon2id hash to verify against

    Returns:
        True if the password matches, False otherwise
    """
    try:
        ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception:
        # Any other error (malformed hash, etc.) = invalid
        return False


def needs_rehash(password_hash: str) -> bool:
    """Check if a password hash needs rehashing.

    Returns True if the hash was created with older/weaker parameters
    and should be rehashed on next successful login.
    """
    return ph.check_needs_rehash(password_hash)


# ── Password Strength Validation ─────────────────────────────────────────

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets security requirements.

    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, ""


# ── JWT Token Creation ───────────────────────────────────────────────────

def create_access_token(
    user_id: str,
    *,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Create a short-lived JWT access token.

    Token claims:
    - sub: User ID (subject)
    - jti: Unique token ID (for revocation tracking)
    - iss: Issuer (auth-service)
    - aud: Audience (auth-service)
    - iat: Issued at
    - exp: Expiration

    Args:
        user_id: The user's UUID as a string
        extra_claims: Additional claims to include (e.g., roles, permissions)

    Returns:
        Signed JWT string
    """
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.jwt.access_token_expire_minutes)

    claims: dict[str, Any] = {
        "sub": user_id,
        "jti": str(uuid.uuid4()),
        "iss": settings.jwt.issuer,
        "aud": settings.jwt.audience,
        "iat": now,
        "exp": expire,
        "type": "access",
    }

    if extra_claims:
        claims.update(extra_claims)

    return jwt.encode(
        claims,
        settings.jwt.secret_key,
        algorithm=settings.jwt.algorithm,
    )


def create_refresh_token(user_id: str) -> tuple[str, str]:
    """Create a refresh token and return both raw token and hash.

    The raw token is sent to the client. Only the hash is stored
    in the database. This ensures that even a database breach
    cannot yield usable refresh tokens.

    Returns:
        Tuple of (raw_token, token_hash)
    """
    # Generate a cryptographically secure random token
    raw_token = secrets.token_urlsafe(64)

    # Hash for storage (SHA-256, fast and deterministic)
    token_hash = hash_token(raw_token)

    return raw_token, token_hash


def hash_token(token: str) -> str:
    """Hash a token using SHA-256 for storage.

    Used for refresh tokens and other tokens that need to be
    verified but never returned from the database.

    Args:
        token: Raw token string

    Returns:
        SHA-256 hex digest
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── JWT Token Validation ─────────────────────────────────────────────────

def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token.

    Validates:
    - Signature (using configured algorithm and secret)
    - Expiration (exp claim)
    - Issuer (iss claim)
    - Audience (aud claim)
    - Token type (must be "access")

    Returns:
        Decoded token claims dict

    Raises:
        InvalidTokenError: If the token is malformed or invalid
        TokenExpiredError: If the token has expired
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.jwt.secret_key,
            algorithms=[settings.jwt.algorithm],
            issuer=settings.jwt.issuer,
            audience=settings.jwt.audience,
        )
    except JWTError as e:
        error_msg = str(e).lower()
        if "expired" in error_msg:
            raise TokenExpiredError() from e
        raise InvalidTokenError(message=f"Invalid token: {e}") from e

    # Verify token type
    if payload.get("type") != "access":
        raise InvalidTokenError(message="Invalid token type")

    return payload


def decode_refresh_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT refresh token.

    Similar to decode_access_token but checks for "refresh" type.

    Returns:
        Decoded token claims dict

    Raises:
        InvalidTokenError: If the token is malformed or invalid
        TokenExpiredError: If the token has expired
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.jwt.secret_key,
            algorithms=[settings.jwt.algorithm],
            issuer=settings.jwt.issuer,
            audience=settings.jwt.audience,
        )
    except JWTError as e:
        error_msg = str(e).lower()
        if "expired" in error_msg:
            raise TokenExpiredError() from e
        raise InvalidTokenError(message=f"Invalid token: {e}") from e

    # Verify token type
    if payload.get("type") != "refresh":
        raise InvalidTokenError(message="Invalid token type")

    return payload


# ── Token Family Utilities ───────────────────────────────────────────────

def generate_token_family() -> str:
    """Generate a unique token family ID.

    A token family groups all refresh tokens from a single login session.
    When a token in a family is reused after revocation, the entire
    family is invalidated (detects token theft).
    """
    return str(uuid.uuid4())
