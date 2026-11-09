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

    def sensitive_data_processor(
        logger: Any, method_name: str, event_dict: dict[str, Any]
    ) -> dict[str, Any]:
        """Filter sensitive data from structlog event dict."""
        # Fields that indicate a value is likely a secret (key-based detection)
        sensitive_key_patterns: set[str] = {
            "password", "password_hash", "secret_key", "token", "access_token",
            "refresh_token", "csrf_token", "session_token", "totp_secret",
            "mfa_code", "authorization", "cookie", "secret", "key", "pin", "otp",
            "code", "jwt", "bearer", "api_key", "private_key", "api_secret",
        }
        
        # Values that are likely secrets (value-based detection for long strings)
        def looks_like_secret(value: str) -> bool:
            if not isinstance(value, str):
                return False
            # JWT tokens (3 parts separated by dots)
            if value.count('.') == 2 and len(value) > 50:
                return True
            # Base64-like strings that are long
            if len(value) >= 32 and all(c.isalnum() or c in '+/=' for c in value):
                return True
            # Hex strings that are long
            if len(value) >= 32 and all(c in '0123456789abcdefABCDEF' for c in value):
                return True
            return False
        
        def redact_value(key: str, value: Any) -> Any:
            if isinstance(value, str):
                key_lower = key.lower()
                # Key-based detection
                for field in sensitive_key_patterns:
                    if field in key_lower:
                        return "[REDACTED]"
                # Value-based detection for likely secrets
                if looks_like_secret(value):
                    return "[REDACTED]"
            return value
        
        redacted: dict[str, Any] = {}
        for key, value in event_dict.items():
            redacted[key] = redact_value(key, value)
        return redacted

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            sensitive_data_processor,  # type: ignore[list-item]
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