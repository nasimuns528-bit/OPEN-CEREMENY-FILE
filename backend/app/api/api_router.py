"""
Unified API Router for VisionTrust.
Mounts health, auth, users, datasets, audit, models, and inference routers.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.datasets import router as datasets_router
from app.api.demonstration import router as demonstration_router
from app.api.health import router as health_router
from app.api.inference import router as inference_router
from app.api.models import router as models_router
from app.api.users import router as users_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(datasets_router)
api_router.include_router(audit_router)
api_router.include_router(models_router)
api_router.include_router(inference_router)
api_router.include_router(dashboard_router)
api_router.include_router(demonstration_router)


