"""
Health check endpoints for VisionTrust.
Provides both /api/health and root /health probes.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["System"])


@router.get("/health", summary="System health probe")
@router.get("/api/health", summary="System health probe (aliased)")
async def health_check() -> dict:
    """Returns standard service health and identity."""
    return {
        "status": "ok",
        "service": "VisionTrust API",
    }
