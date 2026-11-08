"""API router initialization."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import analyses, auth, dashboard

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(analyses.router, prefix="/analyses", tags=["analyses"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])