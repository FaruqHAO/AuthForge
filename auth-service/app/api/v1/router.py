"""V1 API router.

Aggregates all v1 sub-routers into a single router.
Each sub-router handles a specific domain.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.auth import router as auth_router
from app.api.v1.sessions import router as sessions_router
from app.api.v1.users import router as users_router
from app.api.v1.roles import router as roles_router
from app.api.v1.permissions import router as permissions_router

api_v1_router = APIRouter(prefix="/api/v1")

# Health endpoints (no auth required)
api_v1_router.include_router(health_router)

# Authentication endpoints
api_v1_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])

# Session management endpoints
api_v1_router.include_router(sessions_router, prefix="/auth/sessions", tags=["Sessions"])

# Admin endpoints (require ADMIN role)
api_v1_router.include_router(users_router, prefix="/admin/users", tags=["Users"])
api_v1_router.include_router(roles_router, prefix="/admin/roles", tags=["Roles"])
api_v1_router.include_router(permissions_router, prefix="/admin/permissions", tags=["Permissions"])
