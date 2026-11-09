"""Structured logging configuration for PhishGuard CI."""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog

# Context variable for request ID
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """Get current request ID from context."""
    return request_id_var.get()


def set_request_id(request_id: str) -> None:
    """Set request ID in context."""
    request_id_var.set(request_id)


def clear_request_id() -> None:
    """Clear request ID from context."""
    request_id_var.set(None)


class SensitiveDataFilter(logging.Filter):
    """Filter to remove sensitive data from log records."""

    SENSITIVE_FIELDS = {
        "password",
        "password_hash",
        "secret_key",
        "token",
        "access_token",
        "refresh_token",
        "csrf_token",
        "session_token",
        "totp_secret",
        "mfa_code",
        "authorization",
        "cookie",
        "content",
        "message",
        "sms",
        "email",
        "url",
    }

    def filter(self, record: logging.LogRecord) -> bool:
        # Filter sensitive data from log message
        if hasattr(record, "msg") and isinstance(record.msg, str):
            for field in self.SENSITIVE_FIELDS:
                # Simple pattern matching - in production use more sophisticated approach
                if field in record.msg.lower():
                    record.msg = "[REDACTED]"
                    break

        # Filter sensitive data from extra fields
        if hasattr(record, "__dict__"):
            for key in list(record.__dict__.keys()):
                if key.lower() in self.SENSITIVE_FIELDS:
                    record.__dict__[key] = "[REDACTED]"

        return True


def configure_logging() -> None:
    """Configure structlog for structured logging."""
    # Standard library logging setup
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )

    # Add sensitive data filter to root logger
    root_logger = logging.getLogger()
    root_logger.addFilter(SensitiveDataFilter())

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    """Get a structlog logger instance."""
    return structlog.get_logger(name)


# Request logging middleware helper
async def log_request_response(
    logger: structlog.BoundLogger,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    request_id: str | None = None,
    user_id: str | None = None,
) -> None:
    """Log HTTP request/response."""
    logger.info(
        "http_request",
        method=method,
        path=path,
        status_code=status_code,
        duration_ms=duration_ms,
        request_id=request_id,
        user_id=user_id,
    )


async def log_security_event(
    logger: structlog.BoundLogger,
    event_type: str,
    user_id: str | None = None,
    ip_hash: str | None = None,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> None:
    """Log security-related events."""
    logger.warning(
        "security_event",
        event_type=event_type,
        user_id=user_id,
        ip_hash=ip_hash,
        details=details or {},
        request_id=request_id,
    )


async def log_auth_event(
    logger: structlog.BoundLogger,
    event_type: str,
    email: str | None = None,
    user_id: str | None = None,
    success: bool = True,
    ip_hash: str | None = None,
    request_id: str | None = None,
) -> None:
    """Log authentication events."""
    if success:
        logger.info(
            "auth_event",
            event_type=event_type,
            user_id=user_id,
            ip_hash=ip_hash,
            request_id=request_id,
        )
    else:
        logger.warning(
            "auth_event",
            event_type=event_type,
            email=email,  # Only log email on failure for debugging
            ip_hash=ip_hash,
            request_id=request_id,
        )