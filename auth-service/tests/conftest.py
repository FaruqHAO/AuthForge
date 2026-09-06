"""Shared test fixtures.

Provides:
- Async test client (httpx.AsyncClient) bound to the FastAPI app
- Test settings override (testing environment, in-memory DB URL, etc.)
- Mock Redis client for tests that don't need real Redis

Usage:
    pytest automatically discovers conftest.py fixtures.
    Mark tests with @pytest.mark.unit or @pytest.mark.integration.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Set test environment before importing app
os.environ["ENVIRONMENT"] = "testing"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-testing-only-min-32-chars"
os.environ["SECRET_KEY"] = "test-app-secret-key-for-testing-only-min-32-chars"
os.environ["DATABASE_URL"] = (
    "postgresql+asyncpg://test_user:test_pass@localhost:5432/test_auth_db"
)
os.environ["REDIS_URL"] = "redis://localhost:6379/1"
os.environ["DEBUG"] = "true"

from app.core.config import get_settings  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Clear settings cache before each test.

    Ensures each test starts with a fresh settings instance
    so env var overrides in one test don't leak to another.
    """
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Use asyncio backend for async tests."""
    return "asyncio"


@pytest.fixture(scope="session")
def settings():
    """Return test application settings."""
    return get_settings()


@pytest.fixture
def app():
    """Create a fresh FastAPI app for each test.

    The app is created with test settings. Exception handlers
    and middleware are included so tests cover the full stack.
    """
    application = create_app()
    return application


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client for testing API endpoints.

    Uses httpx.ASGITransport to run requests directly through
    the ASGI app without starting a real server.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.fixture
def mock_redis():
    """Mock Redis client for unit tests.

    Provides an AsyncMock that simulates Redis operations
    without requiring a real Redis server.
    """
    mock = AsyncMock()
    mock.ping = AsyncMock(return_value=True)
    mock.get = AsyncMock(return_value=None)
    mock.set = AsyncMock(return_value=True)
    mock.incr = AsyncMock(return_value=1)
    mock.expire = AsyncMock(return_value=True)
    mock.delete = AsyncMock(return_value=1)
    mock.aclose = AsyncMock()
    return mock
