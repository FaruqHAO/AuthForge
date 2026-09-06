"""Async SQLAlchemy database configuration.

Provides:
- Async engine with connection pooling
- Request-scoped session factory
- Declarative Base for all models
- Lifecycle functions for startup/shutdown

The async engine uses asyncpg for non-blocking PostgreSQL access,
which is critical for FastAPI's async request handling.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Naming convention for constraints — ensures consistent migration names
# across environments and makes Alembic autogenerate more reliable.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all ORM models.

    Provides consistent metadata configuration and type annotations
    across the entire model layer.
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    # Type annotation mapping for Pydantic compatibility
    type_annotation_map: dict[type, Any] = {}


# Module-level engine and session factory — initialized during app startup
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return the async engine (must be initialized first)."""
    if _engine is None:
        msg = "Database engine not initialized. Call init_db() first."
        raise RuntimeError(msg)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the session factory (must be initialized first)."""
    if _session_factory is None:
        msg = "Session factory not initialized. Call init_db() first."
        raise RuntimeError(msg)
    return _session_factory


async def init_db() -> None:
    """Initialize database engine and session factory.

    Called during application startup. Creates the async engine
    with connection pooling configured from settings.
    """
    global _engine, _session_factory  # noqa: PLW0603

    settings = get_settings()

    _engine = create_async_engine(
        settings.database.url,
        echo=settings.database.echo,
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
        pool_pre_ping=True,  # Verify connections before checkout
        pool_recycle=3600,   # Recycle connections after 1 hour
    )

    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,  # Prevent lazy-load issues in async context
    )

    logger.info(
        "Database engine initialized",
        extra={"pool_size": settings.database.pool_size},
    )


async def close_db() -> None:
    """Dispose of the database engine pool.

    Called during application shutdown. Ensures all connections are
    properly returned to the pool and closed.
    """
    global _engine, _session_factory  # noqa: PLW0603

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database engine disposed")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a database session.

    Sessions are request-scoped: opened on dependency injection,
    committed/rolled back at the end of the request, and closed
    automatically.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
