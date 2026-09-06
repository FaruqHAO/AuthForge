"""Async Redis connection management.

Redis provides high-performance operations for:
- Rate limiting (sliding window counters with atomic operations)
- Failed login attempt tracking (fast increment with TTL)
- Distributed locks (prevents race conditions in token rotation)
- Token blacklist (if immediate access token invalidation is needed)

NOT used for:
- User data, sessions, roles, permissions (these belong in PostgreSQL)
- Anything that requires complex queries or transactions
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

import redis.asyncio as redis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Module-level connection pool — initialized during app startup
_pool: redis.ConnectionPool | None = None
_client: redis.Redis[bytes] | None = None


def get_redis_sync() -> redis.Redis[bytes]:
    """Return the Redis client (must be initialized first)."""
    if _client is None:
        msg = "Redis client not initialized. Call init_redis() first."
        raise RuntimeError(msg)
    return _client


async def init_redis() -> None:
    """Initialize Redis connection pool and client.

    Called during application startup. Uses hiredis for faster
    protocol parsing when available.
    """
    global _pool, _client  # noqa: PLW0603

    settings = get_settings()

    _pool = redis.ConnectionPool.from_url(
        settings.redis.url,
        max_connections=settings.redis.max_connections,
        decode_responses=False,
    )
    _client = redis.Redis(connection_pool=_pool)

    # Verify connectivity
    try:
        await _client.ping()
        logger.info("Redis connection established")
    except redis.ConnectionError:
        logger.exception("Failed to connect to Redis")
        raise


async def close_redis() -> None:
    """Close Redis connection pool.

    Called during application shutdown.
    """
    global _pool, _client  # noqa: PLW0603

    if _client is not None:
        await _client.aclose()
        _client = None
    if _pool is not None:
        await _pool.disconnect()
        _pool = None
    logger.info("Redis connection closed")


async def get_redis() -> AsyncGenerator[redis.Redis[bytes], None]:
    """FastAPI dependency that yields a Redis client.

    The client is shared across the request — Redis connections are
    lightweight and multiplexed, so per-request pooling is unnecessary.
    """
    client = get_redis_sync()
    yield client
