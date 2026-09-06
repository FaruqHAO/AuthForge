"""Centralized exception handling for FastAPI.

Converts all exceptions into the standard JSON error envelope.
Handles:
- Custom auth exceptions (authentication, authorization, validation, etc.)
- Pydantic validation errors (request body validation)
- SQLAlchemy database errors
- Unexpected/unhandled exceptions (catch-all)

Security principle: Never expose internal exception details, stack traces,
or database errors to clients. Always return generic messages for unexpected
errors and log the actual exception server-side.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.core.exceptions import AuthBaseException, InternalError
from app.api.schemas import ErrorResponse, ErrorDetail

logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers on the FastAPI app.

    Called during app creation. Handlers are evaluated in reverse
    registration order (last registered = first tried), so the
    most specific handlers should be registered last.
    """

    # ── Catch-all for unhandled exceptions (500) ─────────────────────────
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle unexpected exceptions.

        Logs the full traceback server-side but returns a generic
        error to the client. Never leak internal details.
        """
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception(
            "Unhandled exception",
            extra={"extra_data": {"request_id": request_id}},
        )
        response = ErrorResponse(
            error=ErrorDetail(
                code="INTERNAL_ERROR",
                message="An unexpected error occurred",
            )
        )
        return JSONResponse(
            status_code=500,
            content=response.model_dump(),
        )

    # ── Auth base exceptions (401/403/404/409/422/429) ───────────────────
    @app.exception_handler(AuthBaseException)
    async def auth_exception_handler(
        request: Request, exc: AuthBaseException
    ) -> JSONResponse:
        """Handle all custom auth exceptions.

        Uses the status_code and error_code from the exception.
        """
        logger.warning(
            "Auth exception: %s (%s)",
            exc.error_code,
            exc.status_code,
            extra={
                "extra_data": {
                    "error_code": exc.error_code,
                    "path": request.url.path,
                }
            },
        )
        response = ErrorResponse(
            error=ErrorDetail(
                code=exc.error_code,
                message=exc.message,
            )
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=response.model_dump(),
        )

    # ── Request validation errors (422) ──────────────────────────────────
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle FastAPI request validation errors (bad request body/params).

        Formats Pydantic errors into a readable message.
        """
        errors: list[dict[str, Any]] = []
        for error in exc.errors():
            loc = " → ".join(str(item) for item in error["loc"])
            errors.append({
                "field": loc,
                "message": error["msg"],
                "type": error["type"],
            })

        detail = "; ".join(
            f"{e['field']}: {e['message']}" for e in errors
        )

        response = ErrorResponse(
            error=ErrorDetail(
                code="VALIDATION_ERROR",
                message=f"Validation error: {detail}",
            )
        )
        return JSONResponse(
            status_code=422,
            content=response.model_dump(),
        )

    # ── Pydantic validation errors (422) ─────────────────────────────────
    @app.exception_handler(PydanticValidationError)
    async def pydantic_exception_handler(
        request: Request, exc: PydanticValidationError
    ) -> JSONResponse:
        """Handle Pydantic model validation errors."""
        errors = exc.errors()
        detail = "; ".join(
            f"{' → '.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in errors
        )
        response = ErrorResponse(
            error=ErrorDetail(
                code="VALIDATION_ERROR",
                message=f"Validation error: {detail}",
            )
        )
        return JSONResponse(
            status_code=422,
            content=response.model_dump(),
        )

    # ── Database errors (500) ────────────────────────────────────────────
    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(
        request: Request, exc: IntegrityError
    ) -> JSONResponse:
        """Handle database constraint violations.

        Logs the actual error but returns a generic message.
        Constraint violations often indicate data integrity issues.
        """
        logger.error(
            "Database integrity error",
            extra={"extra_data": {"path": request.url.path}},
        )
        response = ErrorResponse(
            error=ErrorDetail(
                code="DATABASE_ERROR",
                message="A data integrity error occurred",
            )
        )
        return JSONResponse(
            status_code=500,
            content=response.model_dump(),
        )

    @app.exception_handler(SQLAlchemyError)
    async def sqlalchemy_error_handler(
        request: Request, exc: SQLAlchemyError
    ) -> JSONResponse:
        """Handle general SQLAlchemy errors."""
        logger.error(
            "Database error",
            extra={"extra_data": {"path": request.url.path}},
        )
        response = ErrorResponse(
            error=ErrorDetail(
                code="DATABASE_ERROR",
                message="A database error occurred",
            )
        )
        return JSONResponse(
            status_code=500,
            content=response.model_dump(),
        )
