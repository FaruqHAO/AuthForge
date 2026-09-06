"""Health check endpoints.

Provides three endpoints for different monitoring needs:
- GET /health — Full health check (DB + Redis connectivity)
- GET /health/live — Liveness probe (is the process running?)
- GET /health/ready — Readiness probe (can it serve traffic?)

These endpoints do NOT require authentication and do NOT expose
sensitive system information (internal IPs, software versions, etc.).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.dependencies import get_db
from app.api.schemas import HealthResponse

router = APIRouter(tags=["Health"])
logger = logging.getLogger(__name__)


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Full health check",
    description="Returns health status including dependent services.",
)
async def health_check(
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    """Full health check — verifies DB and Redis connectivity.

    This is the primary health check endpoint. Load balancers
    and monitoring systems should use this to determine service health.
    """
    services: dict[str, str] = {}

    # Check database
    try:
        # We need to import here to avoid circular imports
        from app.core.database import get_session_factory

        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
        services["database"] = "healthy"
    except Exception:
        logger.warning("Health check: database unhealthy")
        services["database"] = "unhealthy"

    # Check Redis
    try:
        from app.core.redis import get_redis_sync

        client = get_redis_sync()
        await client.ping()
        services["redis"] = "healthy"
    except Exception:
        logger.warning("Health check: redis unhealthy")
        services["redis"] = "unhealthy"

    # Determine overall status
    all_healthy = all(v == "healthy" for v in services.values())
    status = "healthy" if all_healthy else "degraded"

    return HealthResponse(
        status=status,
        version=settings.app_version,
        environment=settings.environment,
        services=services,
    )


@router.get(
    "/health/live",
    response_model=HealthResponse,
    summary="Liveness probe",
    description="Returns 200 if the process is running. Use for k8s liveness.",
)
async def liveness_check(
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    """Liveness probe — simply confirms the process is alive.

    Does NOT check dependent services. If this fails, the orchestrator
    should restart the container.
    """
    return HealthResponse(
        status="alive",
        version=settings.app_version,
        environment=settings.environment,
    )


@router.get(
    "/health/ready",
    response_model=HealthResponse,
    summary="Readiness probe",
    description="Returns 200 if the service can accept traffic.",
)
async def readiness_check(
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    """Readiness probe — confirms the service can handle requests.

    Checks dependent services (DB, Redis). If any are unhealthy,
    the service should be removed from the load balancer pool.
    """
    services: dict[str, str] = {}

    try:
        from app.core.database import get_session_factory

        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
        services["database"] = "ready"
    except Exception:
        services["database"] = "not_ready"

    try:
        from app.core.redis import get_redis_sync

        client = get_redis_sync()
        await client.ping()
        services["redis"] = "ready"
    except Exception:
        services["redis"] = "not_ready"

    all_ready = all(v == "ready" for v in services.values())
    status = "ready" if all_ready else "not_ready"

    return HealthResponse(
        status=status,
        version=settings.app_version,
        environment=settings.environment,
        services=services,
    )
