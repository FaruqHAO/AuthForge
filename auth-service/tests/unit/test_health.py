"""Unit tests for health check endpoints.

Tests the three health endpoints:
- GET /health (full health check)
- GET /health/live (liveness probe)
- GET /health/ready (readiness probe)

These tests verify response structure and status codes.
Database/Redis checks are tested with mocks.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestLivenessProbe:
    """Tests for the liveness probe endpoint."""

    @pytest.mark.asyncio
    async def test_liveness_returns_200(self, client: AsyncClient):
        """Liveness probe should always return 200."""
        response = await client.get("/api/v1/health/live")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_liveness_response_structure(self, client: AsyncClient):
        """Liveness probe should return valid health response structure."""
        response = await client.get("/api/v1/health/live")
        data = response.json()
        assert data["status"] == "alive"
        assert "version" in data
        assert "environment" in data

    @pytest.mark.asyncio
    async def test_liveness_no_services_checked(self, client: AsyncClient):
        """Liveness probe should not include service checks."""
        response = await client.get("/api/v1/health/live")
        data = response.json()
        # Services may be empty or absent for liveness
        assert data.get("services", {}) == {}


class TestHealthCheck:
    """Tests for the full health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_returns_success(self, client: AsyncClient):
        """Health check should return a successful response."""
        response = await client.get("/api/v1/health")
        # Even if DB/Redis are down, the endpoint itself works
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_health_response_structure(self, client: AsyncClient):
        """Health check should return valid response structure."""
        response = await client.get("/api/v1/health")
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "environment" in data
        assert "services" in data
        assert isinstance(data["services"], dict)

    @pytest.mark.asyncio
    async def test_health_status_values(self, client: AsyncClient):
        """Health status should be either 'healthy' or 'degraded'."""
        response = await client.get("/api/v1/health")
        data = response.json()
        assert data["status"] in ("healthy", "degraded")


class TestReadinessProbe:
    """Tests for the readiness probe endpoint."""

    @pytest.mark.asyncio
    async def test_readiness_returns_success(self, client: AsyncClient):
        """Readiness probe should return a successful response."""
        response = await client.get("/api/v1/health/ready")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_readiness_response_structure(self, client: AsyncClient):
        """Readiness probe should return valid response structure."""
        response = await client.get("/api/v1/health/ready")
        data = response.json()
        assert "status" in data
        assert "services" in data
        assert isinstance(data["services"], dict)

    @pytest.mark.asyncio
    async def test_readiness_status_values(self, client: AsyncClient):
        """Readiness status should be either 'ready' or 'not_ready'."""
        response = await client.get("/api/v1/health/ready")
        data = response.json()
        assert data["status"] in ("ready", "not_ready")
