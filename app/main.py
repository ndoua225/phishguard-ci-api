"""PhishGuard CI Agent API - Application factory and main entry point."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import analyses, auth, dashboard
from app.config import settings
from app.db.session import close_db, init_db, set_test_engine


def create_app(database_url: str | None = None) -> FastAPI:
    """Create FastAPI application with optional test database override.
    
    Args:
        database_url: Optional database URL for testing. If None, uses settings.database_url.
    """
    
    @asynccontextmanager
    async def app_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        # Startup
        if database_url:
            # Set up test engine
            set_test_engine(database_url)
        await init_db()
        yield
        # Shutdown
        await close_db()
    
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
