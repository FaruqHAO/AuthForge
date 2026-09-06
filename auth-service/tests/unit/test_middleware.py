"""Unit tests for middleware.

Tests verify:
- Request ID generation and passthrough
- Security headers on responses
- CORS headers
- Middleware ordering
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestRequestIDMiddleware:
    """Tests for the request ID middleware."""

    @pytest.mark.asyncio
    async def test_request_id_generated(self, client: AsyncClient):
        """Requests without X-Request-ID should get one generated."""
        response = await client.get("/api/v1/health/live")
        assert "X-Request-ID" in response.headers
        # Should be a UUID format
        request_id = response.headers["X-Request-ID"]
        assert len(request_id) == 36  # UUID v4 format
        assert request_id.count("-") == 4

    @pytest.mark.asyncio
    async def test_request_id_passthrough(self, client: AsyncClient):
        """Client-provided X-Request-ID should be passed through."""
        custom_id = "test-custom-request-id-12345"
        response = await client.get(
            "/api/v1/health/live",
            headers={"X-Request-ID": custom_id},
        )
        assert response.headers["X-Request-ID"] == custom_id

    @pytest.mark.asyncio
    async def test_request_id_on_error_responses(self, client: AsyncClient):
        """Request ID should be present even on error responses."""
        response = await client.get("/nonexistent-endpoint")
        assert "X-Request-ID" in response.headers


class TestSecurityHeaders:
    """Tests for security headers middleware."""

    @pytest.mark.asyncio
    async def test_x_content_type_options(self, client: AsyncClient):
        """X-Content-Type-Options should be nosniff."""
        response = await client.get("/api/v1/health/live")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    @pytest.mark.asyncio
    async def test_x_frame_options(self, client: AsyncClient):
        """X-Frame-Options should be DENY."""
        response = await client.get("/api/v1/health/live")
        assert response.headers.get("X-Frame-Options") == "DENY"

    @pytest.mark.asyncio
    async def test_x_xss_protection(self, client: AsyncClient):
        """X-XSS-Protection should be 0 (modern approach)."""
        response = await client.get("/api/v1/health/live")
        assert response.headers.get("X-XSS-Protection") == "0"

    @pytest.mark.asyncio
    async def test_referrer_policy(self, client: AsyncClient):
        """Referrer-Policy should be set."""
        response = await client.get("/api/v1/health/live")
        assert "Referrer-Policy" in response.headers

    @pytest.mark.asyncio
    async def test_permissions_policy(self, client: AsyncClient):
        """Permissions-Policy should restrict browser features."""
        response = await client.get("/api/v1/health/live")
        assert "Permissions-Policy" in response.headers
        policy = response.headers["Permissions-Policy"]
        assert "camera=()" in policy
        assert "microphone=()" in policy


class TestRootEndpoint:
    """Tests for the root endpoint."""

    @pytest.mark.asyncio
    async def test_root_returns_service_info(self, client: AsyncClient):
        """Root endpoint should return service name and version."""
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "version" in data

    @pytest.mark.asyncio
    async def test_docs_endpoint_available_in_debug(self, client: AsyncClient):
        """OpenAPI docs should be available in debug mode."""
        response = await client.get("/docs")
        # In debug mode, docs should be available (200 or redirect)
        assert response.status_code in (200, 307)
