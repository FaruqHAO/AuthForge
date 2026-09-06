"""Security headers middleware.

Adds security-critical HTTP headers to all responses following
OWASP recommendations:

- X-Content-Type-Options: nosniff — Prevents MIME type sniffing
- X-Frame-Options: DENY — Prevents clickjacking
- X-XSS-Protection: 0 — Modern browsers handle XSS better than this header
  (CSP is the correct defense). Setting to 0 avoids known bypass issues.
- Strict-Transport-Security: Enforces HTTPS for 1 year
- Referrer-Policy: Limits referrer information leakage
- Permissions-Policy: Restricts browser features

Note: Content-Security-Policy is application-specific and should be
configured per-deployment, so it is not added here.
"""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to all HTTP responses.

    These headers protect against common web security threats.
    They are safe to add in all environments including development.
    """

    HEADERS: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "0",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=()"
        ),
    }

    # Only add HSTS in non-development (avoids issues with local HTTP)
    HSTS_HEADER = "Strict-Transport-Security"
    HSTS_VALUE = "max-age=31536000; includeSubDomains"

    def __init__(self, app, *, is_production: bool = False) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._is_production = is_production

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)

        for header_name, header_value in self.HEADERS.items():
            response.headers[header_name] = header_value

        if self._is_production:
            response.headers[self.HSTS_HEADER] = self.HSTS_VALUE

        return response
