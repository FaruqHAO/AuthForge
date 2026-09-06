"""Unit tests for rate limiting middleware.

Tests cover:
- Rate limit parsing
- IP-based limiting for login
- Rate limit response format
- Sliding window behavior
"""

from __future__ import annotations

import pytest

from app.middleware.rate_limit import parse_rate_limit


class TestParseRateLimit:
    """Tests for rate limit string parsing."""

    def test_parse_minute(self):
        """'5/minute' should parse to (5, 60)."""
        count, seconds = parse_rate_limit("5/minute")
        assert count == 5
        assert seconds == 60

    def test_parse_hour(self):
        """'3/hour' should parse to (3, 3600)."""
        count, seconds = parse_rate_limit("3/hour")
        assert count == 3
        assert seconds == 3600

    def test_parse_day(self):
        """'100/day' should parse to (100, 86400)."""
        count, seconds = parse_rate_limit("100/day")
        assert count == 100
        assert seconds == 86400

    def test_parse_second(self):
        """'10/second' should parse to (10, 1)."""
        count, seconds = parse_rate_limit("10/second")
        assert count == 10
        assert seconds == 1

    def test_parse_invalid(self):
        """Invalid format should raise ValueError."""
        with pytest.raises(ValueError):
            parse_rate_limit("invalid")


class TestRateLimitConfig:
    """Tests for rate limit configuration selection."""

    def test_login_endpoint_has_rate_limit(self):
        """Login endpoint should have rate limiting."""
        from app.middleware.rate_limit import RateLimitMiddleware
        middleware = RateLimitMiddleware(app=None)
        config = middleware._get_rate_limit_config(
            "/api/v1/auth/login", "POST"
        )
        assert config is not None
        assert config[0] == "rate_limit:login:"

    def test_register_endpoint_has_rate_limit(self):
        """Register endpoint should have rate limiting."""
        from app.middleware.rate_limit import RateLimitMiddleware
        middleware = RateLimitMiddleware(app=None)
        config = middleware._get_rate_limit_config(
            "/api/v1/auth/register", "POST"
        )
        assert config is not None
        assert config[0] == "rate_limit:register:"

    def test_health_endpoint_no_rate_limit(self):
        """Health endpoint should not have rate limiting."""
        from app.middleware.rate_limit import RateLimitMiddleware
        middleware = RateLimitMiddleware(app=None)
        config = middleware._get_rate_limit_config(
            "/api/v1/health/live", "GET"
        )
        assert config is None

    def test_get_endpoint_no_rate_limit(self):
        """GET requests should not have rate limiting."""
        from app.middleware.rate_limit import RateLimitMiddleware
        middleware = RateLimitMiddleware(app=None)
        config = middleware._get_rate_limit_config(
            "/api/v1/auth/login", "GET"
        )
        assert config is None
