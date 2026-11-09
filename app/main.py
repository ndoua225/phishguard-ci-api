"""PhishGuard CI Agent API - Application factory and main entry point."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import analyses, auth, dashboard
from app.config import settings
from app.core.logging import (
    configure_logging,
    get_logger,
    log_request_response,
    request_id_var,
)
from app.db.session import close_db, init_db, set_test_engine


def create_app(database_url: str | None = None) -> FastAPI:
    """Create FastAPI application with optional test database override.

    Args:
        database_url: Optional database URL for testing. If None, uses settings.database_url.
    """

    # Configure structured logging
    configure_logging()
    logger = get_logger(__name__)

    @asynccontextmanager
    async def app_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        # Startup
        if database_url:
            # Set up test engine
            set_test_engine(database_url)
        await init_db()
        logger.info("application_startup", environment=settings.environment)
        yield
        # Shutdown
        await close_db()
        logger.info("application_shutdown")

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="PhishGuard CI Agent API - Phishing and fraud detection platform",
        lifespan=app_lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

    # Request logging middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next: Callable[[Request], Awaitable[JSONResponse]]) -> JSONResponse:
        # Generate or extract request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request_id_var.set(request_id)

        start_time = time.perf_counter()

        # Get user ID if authenticated (from Bearer token)
        user_id = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            # We don't decode here to avoid overhead; user_id will be added in logs if needed
            pass

        # Log request
        logger.info(
            "http_request_start",
            method=request.method,
            path=request.url.path,
            request_id=request_id,
        )

        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "http_request_error",
                method=request.method,
                path=request.url.path,
                request_id=request_id,
                duration_ms=round(duration_ms, 2),
                error_type=type(exc).__name__,
            )
            raise

        duration_ms = (time.perf_counter() - start_time) * 1000

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        # Log response
        await log_request_response(
            logger=logger,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
            request_id=request_id,
            user_id=user_id,
        )

        return response

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Callable[[Request], Awaitable[JSONResponse]]) -> JSONResponse:
        """Add security headers to responses."""
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Include API routers
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(analyses.router, prefix="/api/v1/analyses", tags=["analyses"])
    app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])

    @app.get("/health")
    def health() -> dict[str, str]:
        """Health check endpoint."""
        return {
            "status": "ok",
            "environment": settings.environment,
            "version": "0.1.0",
        }

    @app.get("/")
    def root() -> dict[str, str]:
        """Root endpoint."""
        return {
            "name": settings.app_name,
            "version": "0.1.0",
            "docs": "/docs",
            "health": "/health",
        }

    # Global exception handlers
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Not found"},
        )

    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
        # Log error here (without sensitive data)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    return app


# Default app instance for production
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.environment == "development",
    )
