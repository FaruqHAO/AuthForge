"""Request ID middleware for distributed tracing and correlation.

Every request gets a unique UUID v4 ID that:
- Is returned in the response header (X-Request-ID)
- Is available throughout the request lifecycle via context variables
- Can be provided by the client (for distributed tracing across services)

This enables correlating logs, errors, and metrics across service boundaries.
"""

from __future__ import annotations

import uuid
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import request_id_var

logger = logging.getLogger(__name__)

# Header name used for request ID propagation
REQUEST_ID_HEADER = "X-Request-ID"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware that generates or extracts a request ID.

    If the client provides an X-Request-ID header, it is reused
    (enables distributed tracing across services). Otherwise, a
    new UUID v4 is generated.

    The request ID is:
    - Stored in context variables for logging
    - Added to request.state for handler access
    - Returned in the response header
    """

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        # Extract client-provided ID or generate new one
        request_id = request.headers.get(REQUEST_ID_HEADER, "")
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store in context variable for logging
        token = request_id_var.set(request_id)
        try:
            # Store in request state for handler access
            request.state.request_id = request_id

            # Process request
            response: Response = await call_next(request)

            # Add to response headers
            response.headers[REQUEST_ID_HEADER] = request_id
        finally:
            # Reset context variable
            request_id_var.reset(token)

        return response
