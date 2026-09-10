"""
VisionTrust FastAPI Application Factory
========================================
- CORS restricted to configured ALLOWED_ORIGINS (no wildcard in production)
- Centralized exception handling without stack trace disclosure
- Structured application logging
- Audit-logged bootstrap admin creation on first startup
- Modular routing under /api and /api/v1
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.api_router import api_router
from app.core.config import get_settings
from app.core.database import AsyncSessionLocal, Base, engine
from app.core.logging import logger, setup_logging
from app.models import (  # noqa: F401
    AuditEvent,
    Dataset,
    DatasetFile,
    DatasetStatus,
    DatasetVersion,
    InferenceRecord,
    Model,
    ModelApprovalStatus,
    ModelScanStatus,
    ModelSecurityScan,
    ModelStatus,
    ModelVersion,
    User,
)
from app.security.hashing import hash_password
from app.services.audit_service import log_event

setup_logging()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info("VisionTrust backend starting up — environment: %s", settings.environment)

    _is_test = "sqlite" in settings.database_url.lower()

    if not _is_test:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        await _bootstrap_admin()

    logger.info("Startup complete.")
    yield

    logger.info("VisionTrust backend shutting down.")
    if not _is_test:
        await engine.dispose()


async def _bootstrap_admin() -> None:
    """Create the first admin user if the users table is empty."""
    from sqlalchemy import func, select

    async with AsyncSessionLocal() as db:
        count_result = await db.execute(select(func.count()).select_from(User))
        count = count_result.scalar_one()

        if count == 0:
            logger.info("No users found — creating bootstrap admin: %s", settings.first_admin_username)
            admin = User(
                username=settings.first_admin_username.lower(),
                email=settings.first_admin_email.lower(),
                password_hash=hash_password(settings.first_admin_password),
                role="ADMIN",
                is_active=True,
            )
            db.add(admin)
            await db.flush()

            await log_event(
                db,
                action="user.bootstrap_admin",
                actor_id=admin.id,
                actor_username=admin.username,
                resource_type="user",
                resource_id=admin.id,
                details={"source": "system_bootstrap", "role": "ADMIN"},
            )
            await db.commit()
            logger.info("Bootstrap admin created with id=%s", admin.id)


def create_app() -> FastAPI:
    is_production = settings.environment == "production"

    app = FastAPI(
        title="VisionTrust API",
        description=(
            "Trustworthy Computer Vision Integrity Assurance for Data, "
            "Models and Inference Outputs in Multi-Contributor Pipelines."
        ),
        version="1.0.0",
        docs_url=None if is_production else "/docs",
        redoc_url=None if is_production else "/redoc",
        openapi_url=None if is_production else "/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS ────────────────────────────────────────────────────────────────
    # Strict CORS: Whitelist only configured origins (never wildcard in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Centralized Exception Handling (Zero Stack Trace Disclosure) ─────────
    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal error occurred. Please try again."},
        )

    # ── Health Endpoints ────────────────────────────────────────────────────
    @app.get("/health", tags=["System"], include_in_schema=not is_production)
    @app.get("/api/health", tags=["System"], include_in_schema=not is_production)
    async def root_health() -> dict:
        return {"status": "ok", "service": "VisionTrust API"}

    # ── Routers ─────────────────────────────────────────────────────────────
    # Mount under /api as specified in Phase 0 & Phase 1
    app.include_router(api_router, prefix="/api")

    # Also mount under /api/v1 for backwards compatibility
    app.include_router(api_router, prefix="/api/v1")

    return app


app = create_app()
