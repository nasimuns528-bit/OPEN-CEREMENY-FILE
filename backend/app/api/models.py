"""
Model Registry API router for Phase 4.
Handles:
- Model catalog creation
- Model version weights uploading and automated static security scan
- Reviewer approval workflow with Ed25519 asymmetric cryptographic signing
- Disk-level integrity and signature re-verification
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.model import ModelVersion
from app.models.user import User
from app.schemas.model import (
    ModelCreate,
    ModelDetailResponse,
    ModelResponse,
    ModelVerifyResponse,
    ModelVersionResponse,
)
from app.security.dependencies import get_client_ip, get_current_user, require_role
from app.services import model_service
from app.utils.storage import compute_file_hash_on_disk, UPLOAD_BASE_DIR

router = APIRouter(prefix="/models", tags=["models"])


@router.post(
    "",
    response_model=ModelResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new model catalog entry (Model Contributor / Admin)",
)
async def create_model(
    payload: ModelCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("MODEL_CONTRIBUTOR", "ADMIN")),
):
    ip_addr = get_client_ip(request)
    model = await model_service.create_model(
        db,
        name=payload.name,
        description=payload.description,
        framework=payload.framework,
        model_type=payload.model_type,
        current_user=current_user,
        ip_address=ip_addr,
    )
    await db.commit()
    await db.refresh(model)
    return ModelResponse(
        id=model.id,
        name=model.name,
        description=model.description,
        framework=model.framework,
        model_type=model.model_type,
        owner_id=model.owner_id,
        owner_username=model.owner_username,
        status=model.status,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


@router.get(
    "",
    response_model=List[ModelResponse],
    summary="List all registered models",
)
async def list_models(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    models = await model_service.list_models(db, skip=skip, limit=limit)
    response: List[ModelResponse] = []
    for m in models:
        versions = m.versions or []
        latest_v = versions[0] if versions else None
        response.append(
            ModelResponse(
                id=m.id,
                name=m.name,
                description=m.description,
                framework=m.framework,
                model_type=m.model_type,
                owner_id=m.owner_id,
                owner_username=m.owner_username,
                status=m.status,
                created_at=m.created_at,
                updated_at=m.updated_at,
                latest_version=latest_v.version_tag if latest_v else None,
                latest_hash=latest_v.sha256_hash if latest_v else None,
                latest_approval=latest_v.approval_status if latest_v else None,
            )
        )
    return response


@router.get(
    "/{model_id}",
    response_model=ModelDetailResponse,
    summary="Get model details with version history and security scans",
)
async def get_model_detail(
    model_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    model = await model_service.get_model(db, model_id, include_versions=True)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model '{model_id}' not found.",
        )

    versions = model.versions or []
    latest_v = versions[0] if versions else None

    return ModelDetailResponse(
        id=model.id,
        name=model.name,
        description=model.description,
        framework=model.framework,
        model_type=model.model_type,
        owner_id=model.owner_id,
        owner_username=model.owner_username,
        status=model.status,
        created_at=model.created_at,
        updated_at=model.updated_at,
        latest_version=latest_v.version_tag if latest_v else None,
        latest_hash=latest_v.sha256_hash if latest_v else None,
        latest_approval=latest_v.approval_status if latest_v else None,
        versions=[ModelVersionResponse.model_validate(v) for v in versions],
    )


@router.post(
    "/{model_id}/versions",
    response_model=ModelVersionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload model weights file and run static security scan (Model Contributor / Admin)",
)
async def upload_model_version(
    model_id: str,
    request: Request,
    version_tag: str = Form(...),
    associated_dataset_version: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("MODEL_CONTRIBUTOR", "ADMIN")),
):
    model = await model_service.get_model(db, model_id, include_versions=False)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model '{model_id}' not found.",
        )

    ip_addr = get_client_ip(request)
    try:
        mv = await model_service.upload_model_version(
            db,
            model=model,
            version_tag=version_tag,
            original_filename=file.filename or "model_weights.pt",
            stream=file.file,
            associated_dataset_version=associated_dataset_version,
            current_user=current_user,
            ip_address=ip_addr,
        )
        await db.commit()
        loaded = (
            await db.execute(
                select(ModelVersion)
                .options(selectinload(ModelVersion.scans))
                .where(ModelVersion.id == mv.id)
            )
        ).scalar_one()
        return ModelVersionResponse.model_validate(loaded)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/{model_id}/versions/{version_id}/approve",
    response_model=ModelVersionResponse,
    summary="Approve model version and generate Ed25519 signature (Reviewer / Admin)",
)
async def approve_model_version(
    model_id: str,
    version_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("REVIEWER", "ADMIN")),
):
    res = await db.execute(
        select(ModelVersion).where(
            ModelVersion.id == version_id,
            ModelVersion.model_id == model_id,
        )
    )
    mv = res.scalar_one_or_none()
    if not mv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version '{version_id}' not found.",
        )

    ip_addr = get_client_ip(request)
    try:
        approved_mv = await model_service.approve_model_version(
            db,
            model_version=mv,
            current_user=current_user,
            ip_address=ip_addr,
        )
        await db.commit()
        loaded = (
            await db.execute(
                select(ModelVersion)
                .options(selectinload(ModelVersion.scans))
                .where(ModelVersion.id == approved_mv.id)
            )
        ).scalar_one()
        return ModelVersionResponse.model_validate(loaded)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/{model_id}/versions/{version_id}/verify",
    response_model=ModelVerifyResponse,
    summary="On-demand verification of model file hash, scan, and Ed25519 signature",
)
async def verify_model(
    model_id: str,
    version_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    res = await db.execute(
        select(ModelVersion).where(
            ModelVersion.id == version_id,
            ModelVersion.model_id == model_id,
        )
    )
    mv = res.scalar_one_or_none()
    if not mv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version '{version_id}' not found.",
        )

    disk_path = UPLOAD_BASE_DIR / mv.storage_path
    current_hash = compute_file_hash_on_disk(disk_path) if disk_path.exists() else "FILE_NOT_FOUND"

    is_eligible, message, diag = model_service.verify_model_eligibility(mv)

    return ModelVerifyResponse(
        model_id=mv.model_id,
        version_tag=mv.version_tag,
        file_hash_match=diag["hash_match"],
        expected_hash=mv.sha256_hash,
        current_hash=current_hash,
        scan_status=mv.security_scan_status,
        approval_status=mv.approval_status,
        signature_valid=diag["signature_valid"],
        deployment_eligible=is_eligible,
        message=message,
    )
