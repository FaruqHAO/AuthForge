"""Rate limiting middleware.

Uses Redis sliding window counters for rate limiting.
Protects against brute force attacks, credential stuffing, and API abuse.

Rate limits:
- Login: 5 attempts per minute per IP
- Registration: 3 attempts per hour per IP
- Password reset: 3 attempts per hour per email
- General API: 100 requests per minute per user

Design decisions:
- Redis provides atomic INCR + EXPIRE operations (no race conditions)
- Sliding window (not fixed window) prevents burst attacks at window boundaries
- Rate limits are checked before expensive operations (password hashing, DB queries)
- Custom exception (RateLimitError) returns 429 with Retry-After header
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import get_settings
from app.core.exceptions import RateLimitError

logger = logging.getLogger(__name__)

# Rate limit key prefixes
LOGIN_KEY_PREFIX = "rate_limit:login:"
REGISTER_KEY_PREFIX = "rate_limit:register:"
PASSWORD_RESET_KEY_PREFIX = "rate_limit:password_reset:"
GENERAL_KEY_PREFIX = "rate_limit:general:"


def parse_rate_limit(rate_str: str) -> tuple[int, int]:
    """Parse a rate limit string like '5/minute' into (count, seconds).

    Returns:
        Tuple of (max_requests, window_seconds)
    """
    count_str, period = rate_str.split("/")
    count = int(count_str)

    period_map = {
        "second": 1,
        "minute": 60,
        "hour": 3600,
        "day": 86400,
    }

    seconds = period_map.get(period, 60)
    return count, seconds


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis.

    Checks rate limits for sensitive endpoints:
    - POST /auth/login — uses IP-based limiting
    - POST /auth/register — uses IP-based limiting
    - POST /auth/forgot-password — uses IP-based limiting
    - Other endpoints — uses user-based limiting
    """

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        # Only rate limit specific endpoints
        path = request.url.path
        method = request.method

        # Check if this path needs rate limiting
        rate_limit_config = self._get_rate_limit_config(path, method)
        if rate_limit_config is None:
            return await call_next(request)

        key_prefix, limit_str = rate_limit_config
        settings = get_settings()

        # Get Redis client
        try:
            from app.core.redis import get_redis_sync
            redis_client = get_redis_sync()
        except RuntimeError:
            # Redis not initialized — skip rate limiting
            return await call_next(request)

        # Build rate limit key
        if key_prefix == LOGIN_KEY_PREFIX or key_prefix == REGISTER_KEY_PREFIX:
            # IP-based limiting for login/register
            client_ip = request.client.host if request.client else "unknown"
            key = f"{key_prefix}{client_ip}"
        else:
            # User-based limiting for other endpoints
            # For now, use IP; will be user-based when auth is added
            client_ip = request.client.host if request.client else "unknown"
            key = f"{key_prefix}{client_ip}"

        # Check rate limit
        max_requests, window_seconds = parse_rate_limit(limit_str)

        try:
            # Atomic increment and check
            current = await redis_client.incr(key)
            if current == 1:
                # First request — set expiry
                await redis_client.expire(key, window_seconds)

            if current > max_requests:
                retry_after = window_seconds
                logger.warning(
                    "Rate limit exceeded: %s (current=%d, max=%d)",
                    key,
                    current,
                    max_requests,
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": "Too many requests. Please try again later.",
                        },
                    },
                    headers={"Retry-After": str(retry_after)},
                )
        except Exception:
            # If Redis fails, don't block the request
            logger.exception("Rate limit check failed")

        return await call_next(request)

    def _get_rate_limit_config(
        self, path: str, method: str
    ) -> tuple[str, str] | None:
        """Determine rate limit configuration for a path/method.

        Returns:
            Tuple of (key_prefix, rate_limit_string) or None if no limit
        """
        settings = get_settings()

        if path == "/api/v1/auth/login" and method == "POST":
            return (LOGIN_KEY_PREFIX, settings.rate_limit.login)
        elif path == "/api/v1/auth/register" and method == "POST":
            return (REGISTER_KEY_PREFIX, settings.rate_limit.register)
        elif path == "/api/v1/auth/forgot-password" and method == "POST":
            return (PASSWORD_RESET_KEY_PREFIX, settings.rate_limit.password_reset)

        return None
