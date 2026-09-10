"""
Trust Dashboard API router for Phase 7.
Exposes real-time Trust Assurance Metrics, 6-component scoring breakdown,
pipeline health summaries, and active security alerts.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.schemas.dashboard import TrustMetricsResponse
from app.security.dependencies import get_current_user
from app.services import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get(
    "/metrics",
    response_model=TrustMetricsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get real-time Integrity Assurance Score and pipeline security posture",
)
async def get_dashboard_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns the real-time Integrity Assurance Score (0-100), detailed scoring breakdown
    across 6 security components, pipeline status cards, and active alerts.
    """
    return await dashboard_service.get_trust_metrics(db)