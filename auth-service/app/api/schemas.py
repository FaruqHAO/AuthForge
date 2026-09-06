"""API response schemas.

Provides the standard envelope format for all API responses:

    Success: {"success": true, "data": {...}, "message": "..."}
    Error:   {"success": false, "error": {"code": "...", "message": "..."}}

This ensures clients always receive a predictable response structure
regardless of the endpoint or error type.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    """Error details within an error response."""

    code: str = Field(
        ...,
        description="Machine-readable error code (e.g., INVALID_CREDENTIALS)",
        examples=["INVALID_CREDENTIALS"],
    )
    message: str = Field(
        ...,
        description="Human-readable error message",
        examples=["Invalid email or password"],
    )


class SuccessResponse(BaseModel, Generic[T]):
    """Standard success response envelope.

    The `data` field contains the actual response payload.
    The `message` field provides a human-readable description.
    """

    success: bool = Field(default=True, description="Indicates successful operation")
    data: T | None = Field(default=None, description="Response payload")
    message: str = Field(default="Operation successful", description="Status message")


class ErrorResponse(BaseModel):
    """Standard error response envelope.

    Never exposes internal details like stack traces, database errors,
    or implementation specifics.
    """

    success: bool = Field(default=False, description="Indicates failed operation")
    error: ErrorDetail = Field(..., description="Error details")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(description="Overall health status")
    version: str = Field(description="Application version")
    environment: str = Field(description="Current environment")
    services: dict[str, str] = Field(
        default_factory=dict,
        description="Status of dependent services",
    )


class MessageResponse(BaseModel):
    """Generic message-only response."""

    success: bool = Field(default=True)
    message: str = Field(description="Response message")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated list response."""

    success: bool = Field(default=True)
    data: list[T] = Field(default_factory=list)
    total: int = Field(description="Total number of items")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    message: str = Field(default="Operation successful")
