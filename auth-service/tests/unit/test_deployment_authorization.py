"""Authorization factories must be callable when FastAPI registers routes."""

import pytest

from app.api.v1.deps import require_permission, require_role
from app.core.exceptions import InsufficientPermissionsError, PermissionDeniedError


@pytest.mark.asyncio
async def test_role_factory_checks_claims():
    dependency = require_role("ADMIN")
    payload = {"roles": ["ADMIN"]}
    assert await dependency(payload) == payload
    with pytest.raises(InsufficientPermissionsError):
        await dependency({"roles": ["USER"]})


@pytest.mark.asyncio
async def test_permission_factory_checks_claims():
    dependency = require_permission("users.delete")
    payload = {"permissions": ["users.delete"]}
    assert await dependency(payload) == payload
    with pytest.raises(PermissionDeniedError):
        await dependency({"permissions": []})
