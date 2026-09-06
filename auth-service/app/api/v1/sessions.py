"""Session management API routes.

Endpoints:
- GET  /auth/sessions — List active sessions for current user
- DELETE /auth/sessions/{session_id} — Revoke a specific session
- DELETE /auth/sessions — Revoke all sessions

These endpoints help users manage their active sessions
and revoke access from compromised devices.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.core.exceptions import SessionNotFoundError
from app.api.schemas import SuccessResponse
from app.api.v1.deps import CurrentUser, get_user_id_from_payload
from app.schemas.auth import SessionInfo
from app.models.session import Session

router = APIRouter()


@router.get(
    "",
    response_model=SuccessResponse[list[SessionInfo]],
    summary="List active sessions",
    description="Get all active sessions for the current user.",
)
async def list_sessions(
    payload: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[list[SessionInfo]]:
    """List all active sessions for the current user."""
    user_id = get_user_id_from_payload(payload)

    result = await db.execute(
        select(Session).where(
            Session.user_id == user_id,
            Session.revoked_at.is_(None),
        ).order_by(Session.created_at.desc())
    )
    sessions = result.scalars().all()

    return SuccessResponse(
        data=[SessionInfo.model_validate(s) for s in sessions],
        message=f"Found {len(sessions)} active sessions",
    )


@router.delete(
    "/{session_id}",
    response_model=SuccessResponse[None],
    summary="Revoke session",
    description="Revoke a specific session by ID.",
    responses={
        404: {"description": "Session not found"},
    },
)
async def revoke_session(
    session_id: uuid.UUID,
    payload: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[None]:
    """Revoke a specific session."""
    user_id = get_user_id_from_payload(payload)

    result = await db.execute(
        select(Session).where(
            Session.id == session_id,
            Session.user_id == user_id,
        )
    )
    session = result.scalar_one_or_none()

    if session is None:
        raise SessionNotFoundError()

    from datetime import UTC, datetime
    session.revoked_at = datetime.now(UTC)

    # Also revoke all refresh tokens in this session
    from app.models.refresh_token import RefreshToken
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.session_id == session_id,
            RefreshToken.is_revoked == False,  # noqa: E712
        )
    )
    tokens = result.scalars().all()
    for token in tokens:
        token.is_revoked = True
        token.rotated_at = datetime.now(UTC)

    await db.flush()

    return SuccessResponse(message="Session revoked successfully")


@router.delete(
    "",
    response_model=SuccessResponse[None],
    summary="Revoke all sessions",
    description="Revoke all active sessions for the current user.",
)
async def revoke_all_sessions(
    payload: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> SuccessResponse[None]:
    """Revoke all active sessions for the current user."""
    user_id = get_user_id_from_payload(payload)

    from datetime import UTC, datetime

    # Revoke all active sessions
    result = await db.execute(
        select(Session).where(
            Session.user_id == user_id,
            Session.revoked_at.is_(None),
        )
    )
    sessions = result.scalars().all()
    for session in sessions:
        session.revoked_at = datetime.now(UTC)

    # Revoke all active refresh tokens
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False,  # noqa: E712
        )
    )
    tokens = result.scalars().all()
    for token in tokens:
        token.is_revoked = True
        token.rotated_at = datetime.now(UTC)

    await db.flush()

    return SuccessResponse(
        message=f"Revoked {len(sessions)} sessions and {len(tokens)} tokens"
    )
