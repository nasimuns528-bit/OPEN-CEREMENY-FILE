"""
Computer Vision Inference API router for Phase 5.
Enforces:
- Pre-inference verification of model integrity, scan, and Ed25519 signature
- Generation of structured bounding boxes and confidence scores
- Output evidence hashing and Ed25519 asymmetric signature issuance
- Trustworthy terminology in responses
"""
from __future__ import annotations

import json
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
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.model import InferenceRecord, Model, ModelVersion
from app.models.user import User
from app.schemas.inference import (
    DetectionItem,
    InferenceRecordResponse,
    InferenceResponse,
    InferenceVerifyResponse,
)
from app.security.dependencies import get_client_ip, get_current_user, require_role
from app.services import inference_service

router = APIRouter(prefix="/inference", tags=["inference"])


@router.post(
    "/detect",
    response_model=InferenceResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Computer Vision inference with cryptographic integrity verification",
)
async def run_inference(
    request: Request,
    model_id: str = Form(...),
    version_id: Optional[str] = Form(None),
    image: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("INFERENCE_USER", "REVIEWER", "ADMIN")),
):
    ip_addr = get_client_ip(request)

    # 1. Fetch model version
    if version_id:
        v_query = select(ModelVersion).where(
            ModelVersion.id == version_id,
            ModelVersion.model_id == model_id,
        )
    else:
        # Fetch latest version
        v_query = (
            select(ModelVersion)
            .where(ModelVersion.model_id == model_id)
            .order_by(ModelVersion.created_at.desc())
            .limit(1)
        )

    res = await db.execute(v_query)
    model_version = res.scalar_one_or_none()
    if not model_version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version not found for model '{model_id}'.",
        )

    # 2. Read raw image bytes safely
    image_bytes = await image.read()
    filename = image.filename or "input_image.jpg"

    # 3. Execute verified inference pipeline
    try:
        inference_resp = await inference_service.execute_verified_inference(
            db,
            model_version=model_version,
            image_filename=filename,
            image_bytes=image_bytes,
            current_user=current_user,
            ip_address=ip_addr,
        )
        return inference_resp
    except ValueError as e:
        # Blocks inference with explicit 400 status code detailing why
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/records",
    response_model=List[InferenceRecordResponse],
    summary="List historical verified inference evidence records",
)
async def list_inference_records(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(InferenceRecord)
        .order_by(InferenceRecord.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    records = list(result.scalars().all())

    response: List[InferenceRecordResponse] = []
    for r in records:
        try:
            preds_raw = json.loads(r.predictions_json)
            preds = [DetectionItem(**p) for p in preds_raw]
        except Exception:
            preds = []

        response.append(
            InferenceRecordResponse(
                id=r.id,
                input_filename=r.input_filename,
                input_hash=r.input_hash,
                model_id=r.model_id,
                model_version_tag=r.model_version_tag,
                model_hash=r.model_hash,
                highest_confidence=r.highest_confidence,
                output_hash=r.output_hash,
                evidence_signature=r.evidence_signature,
                verification_status=r.verification_status,
                executor_username=r.executor_username,
                created_at=r.created_at,
                predictions=preds,
            )
        )
    return response


@router.get(
    "/records/{record_id}",
    response_model=InferenceRecordResponse,
    summary="Get detailed cryptographic evidence record by ID",
)
async def get_inference_record(
    record_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(InferenceRecord).where(InferenceRecord.id == record_id)
    )
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Inference record '{record_id}' not found.",
        )

    try:
        preds_raw = json.loads(r.predictions_json)
        preds = [DetectionItem(**p) for p in preds_raw]
    except Exception:
        preds = []

    return InferenceRecordResponse(
        id=r.id,
        input_filename=r.input_filename,
        input_hash=r.input_hash,
        model_id=r.model_id,
        model_version_tag=r.model_version_tag,
        model_hash=r.model_hash,
        highest_confidence=r.highest_confidence,
        output_hash=r.output_hash,
        evidence_signature=r.evidence_signature,
        verification_status=r.verification_status,
        executor_username=r.executor_username,
        created_at=r.created_at,
        predictions=preds,
    )


@router.post(
    "/{inference_id}/verify",
    response_model=InferenceVerifyResponse,
    summary="Verify historical inference evidence record integrity and cryptographic signature",
)
async def verify_inference(
    inference_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return await inference_service.verify_inference_record(db, inference_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

