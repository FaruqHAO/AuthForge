"""Structured logging configuration.

Provides:
- JSON logging for production (machine-parseable)
- Human-readable logging for development
- Request context integration (request ID, user ID)
- Sensitive field masking (passwords, tokens)

Security note: Never log passwords, raw tokens, or other secrets.
The mask_sensitive_data filter ensures these are redacted.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# Context variables for request-scoped logging context
request_id_var: ContextVar[str] = ContextVar(
    "request_id", default=""
)
user_id_var: ContextVar[str] = ContextVar(
    "user_id", default=""
)

# Fields that should be masked in logs
SENSITIVE_FIELDS: frozenset[str] = frozenset({
    "password",
    "password_hash",
    "new_password",
    "old_password",
    "refresh_token",
    "access_token",
    "reset_token",
    "verification_token",
    "secret_key",
    "jwt_secret_key",
    "smtp_password",
    "database_url",
})


class RequestContextFilter(logging.Filter):
    """Inject request context (request_id, user_id) into all log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get("")  # type: ignore[attr-defined]
        record.user_id = user_id_var.get("")  # type: ignore[attr-defined]
        return True


class SensitiveDataFilter(logging.Filter):
    """Redact sensitive fields from log records.

    Scans the log message and any `extra` dict for sensitive field names,
    replacing their values with `[REDACTED]`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, "extra_data") and isinstance(
            record.extra_data, dict
        ):
            record.extra_data = self._mask_dict(record.extra_data)  # type: ignore[attr-defined]
        return True

    @staticmethod
    def _mask_dict(data: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of the dict with sensitive values masked."""
        masked: dict[str, Any] = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in SENSITIVE_FIELDS):
                masked[key] = "[REDACTED]"
            else:
                masked[key] = value
        return masked


class JSONFormatter(logging.Formatter):
    """JSON log formatter for production environments.

    Outputs one JSON object per line (structured logging).
    Includes timestamp, level, logger name, message, and request context.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", ""),
            "user_id": getattr(record, "user_id", ""),
        }

        # Include extra data if present
        extra_data = getattr(record, "extra_data", None)
        if extra_data and isinstance(extra_data, dict):
            log_entry["data"] = extra_data

        # Include exception info if present
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }

        return json.dumps(log_entry, default=str, ensure_ascii=False)


class DevelopmentFormatter(logging.Formatter):
    """Human-readable log formatter for development.

    Colorized output with short timestamps and request context.
    """

    COLORS: dict[str, str] = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[1;31m",  # Bold Red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        request_id = getattr(record, "request_id", "")
        user_id = getattr(record, "user_id", "")

        parts = [
            f"{color}{record.levelname:<8}{self.RESET}",
            f"{record.name}",
            f"[{request_id[:8]}]" if request_id else "",
            f"({user_id[:8]})" if user_id else "",
            record.getMessage(),
        ]

        if record.exc_info and record.exc_info[1] is not None:
            parts.append(f"\n{self.formatException(record.exc_info)}")

        return " ".join(filter(None, parts))


def setup_logging(environment: str = "development") -> None:
    """Configure application logging.

    Args:
        environment: Current environment. Controls formatter selection.
            - "development": Human-readable, colorized output
            - "production"/"staging": JSON structured output
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Select formatter based on environment
    if environment in ("production", "staging"):
        formatter: logging.Formatter = JSONFormatter()
    else:
        formatter = DevelopmentFormatter()

    # Console handler (stdout for INFO+, stderr for WARNING+)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.INFO)
    stdout_handler.setFormatter(formatter)
    stdout_handler.addFilter(RequestContextFilter())
    stdout_handler.addFilter(SensitiveDataFilter())
    root_logger.addHandler(stdout_handler)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)
    stderr_handler.addFilter(RequestContextFilter())
    stderr_handler.addFilter(SensitiveDataFilter())
    root_logger.addHandler(stderr_handler)

    # Quieten noisy third-party loggers
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("redis").setLevel(logging.WARNING)

    logging.info(
        "Logging initialized",
        extra={"extra_data": {"environment": environment}},
    )


def generate_request_id() -> str:
    """Generate a unique request ID for correlation tracking."""
    return str(uuid.uuid4())
