"""FastAPI application factory and entry point.

Creates the FastAPI application with:
- Lifespan management (startup/shutdown for DB, Redis, etc.)
- Middleware stack (request ID, security headers, CORS)
- Exception handlers (custom errors → JSON envelope)
- API router (versioned endpoints)
- OpenAPI documentation

Dual-mode deployment:
- Standalone: python -m app.main or uvicorn app.main:app
- Importable: from app.main import create_app

Design: The create_app() factory function ensures every instance
gets its own isolated state — critical for testing.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import close_db, init_db
from app.core.logging import setup_logging
from app.core.redis import close_redis, init_redis
from app.api.exception_handlers import register_exception_handlers
from app.api.schemas import ErrorResponse
from app.api.v1.router import api_v1_router
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager.

    Handles startup and shutdown events:
    - Startup: initialize database engine, Redis connection pool, logging
    - Shutdown: dispose database connections, close Redis pool

    This is preferred over deprecated @app.on_event() decorators.
    """
    settings = get_settings()

    # ── Startup ──────────────────────────────────────────────────────────
    setup_logging(environment=settings.environment)
    logger.info(
        "Starting %s v%s [%s]",
        settings.app_name,
        settings.app_version,
        settings.environment,
    )

    await init_db()
    await init_redis()

    logger.info("Application started successfully")

    yield  # Application is running

    # ── Shutdown ─────────────────────────────────────────────────────────
    logger.info("Shutting down application...")
    await close_redis()
    await close_db()
    logger.info("Application shut down cleanly")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    This factory function returns a fully configured FastAPI instance
    with all middleware, exception handlers, and routers registered.
    """
    settings = get_settings()

    # Create app with metadata for OpenAPI documentation
    app = FastAPI(
        title=settings.app_name,
        description=(
            "Production-ready authentication and authorization service. "
            "Supports JWT tokens, refresh token rotation, RBAC, "
            "session management, and audit logging."
        ),
        version=settings.app_version,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
        # Default error response schema for OpenAPI
        responses={
            401: {
                "description": "Authentication required",
                "model": ErrorResponse,
            },
            403: {
                "description": "Insufficient permissions",
                "model": ErrorResponse,
            },
            422: {
                "description": "Validation error",
                "model": ErrorResponse,
            },
            500: {
                "description": "Internal server error",
                "model": ErrorResponse,
            },
        },
    )

    # ── Middleware (order matters: last added = first executed) ───────────

    # CORS — must be added first so it wraps all other middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors.allowed_origins,
        allow_credentials=settings.cors.allow_credentials,
        allow_methods=settings.cors.allow_methods,
        allow_headers=settings.cors.allow_headers,
    )

    # Security headers
    app.add_middleware(
        SecurityHeadersMiddleware,
        is_production=settings.is_production,
    )

    # Rate limiting
    app.add_middleware(RateLimitMiddleware)

    # Request ID — must be near the outside so it wraps everything
    app.add_middleware(RequestIDMiddleware)

    # ── Exception handlers ───────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers ──────────────────────────────────────────────────────────
    app.include_router(api_v1_router)

    # ── Root endpoint ────────────────────────────────────────────────────
    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "docs": "/docs" if settings.debug else "disabled",
        }

    return app


# Module-level app instance for uvicorn / gunicorn
app = create_app()


def run() -> None:
    """Entry point for running the application directly."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="info" if not settings.debug else "debug",
    )


if __name__ == "__main__":
    run()
