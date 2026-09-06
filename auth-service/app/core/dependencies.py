"""Centralized FastAPI dependencies.

Provides reusable dependency functions for:
- Settings injection
- Database session management
- Redis client access
- Request context extraction

Usage in route handlers:
    @router.get("/example")
    async def example(
        settings: Settings = Depends(get_settings_dep),
        db: AsyncSession = Depends(get_db),
    ):
        ...
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import Request
from pydantic_settings import BaseSettings
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db as _get_db
from app.core.logging import request_id_var, user_id_var
from app.core.redis import get_redis as _get_redis

try:
    import redis.asyncio as redis
except ImportError:
    redis = None  # type: ignore[assignment]


async def get_settings_dep() -> Settings:
    """FastAPI dependency that provides application settings."""
    return get_settings()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database sessions.

    Yields an async SQLAlchemy session that is automatically
    committed or rolled back at the end of the request.
    """
    async for session in _get_db():
        yield session


async def get_redis() -> AsyncGenerator[redis.Redis[bytes], None]:  # type: ignore[name-defined]
    """FastAPI dependency for Redis client.

    Yields an async Redis client. The connection is shared
    across the request lifecycle.
    """
    async for client in _get_redis():
        yield client


def get_request_id(request: Request) -> str:
    """Extract the request ID from request state.

    The request ID middleware sets this value on every request.
    Falls back to the context variable if middleware hasn't run yet.
    """
    return getattr(request.state, "request_id", request_id_var.get(""))


def get_current_user_id() -> str | None:
    """Extract the current authenticated user ID from context.

    Returns None if no user is authenticated. Used in services
    that need to know who initiated an action.
    """
    uid = user_id_var.get("")
    return uid if uid else None
