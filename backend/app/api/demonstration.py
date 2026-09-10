"""
Controlled Integrity Attack Demonstration API router for Phase 8.
Restricted to ADMIN and REVIEWER roles.
Executes non-offensive simulated tampering scenarios on local test assets to prove
VisionTrust detection and alerting mechanisms.
"""
from __future__ import annotations

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.schemas.demonstration import AttackDemonstrationResponse
from app.security.dependencies import require_role
from app.services import demonstration_service

router = APIRouter(prefix="/demonstration", tags=["demonstration"])


@router.post(
    "/attack-1-dataset-tamper",
    response_model=AttackDemonstrationResponse,
    status_code=status.HTTP_200_OK,
    summary="Attack 1: Dataset file modification on disk detecting DATA INTEGRITY FAILURE",
)
async def execute_attack_1(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "REVIEWER")),
):
    return await demonstration_service.run_attack_1_dataset_tamper(db, current_user)


@router.post(
    "/attack-2-model-tamper",
    response_model=AttackDemonstrationResponse,
    status_code=status.HTTP_200_OK,
    summary="Attack 2: Model weights tampering detecting MODEL INTEGRITY FAILURE and blocking inference",
)
async def execute_attack_2(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "REVIEWER")),
):
    return await demonstration_service.run_attack_2_model_tamper(db, current_user)


@router.post(
    "/attack-3-inference-tamper",
    response_model=AttackDemonstrationResponse,
    status_code=status.HTTP_200_OK,
    summary="Attack 3: Inference evidence alteration detecting INFERENCE EVIDENCE INVALID",
)
async def execute_attack_3(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "REVIEWER")),
):
    return await demonstration_service.run_attack_3_inference_tamper(db, current_user)


@router.post(
    "/attack-4-audit-tamper",
    response_model=AttackDemonstrationResponse,
    status_code=status.HTTP_200_OK,
    summary="Attack 4: Audit trail historical alteration detecting AUDIT CHAIN INVALID",
)
async def execute_attack_4(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "REVIEWER")),
):
    return await demonstration_service.run_attack_4_audit_tamper(db, current_user)


@router.get(
    "/scenarios",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List available controlled integrity demonstration scenarios",
)
async def get_demonstration_scenarios(
    current_user: User = Depends(require_role("ADMIN", "REVIEWER")),
):
    return [
        {
            "id": "attack_1_dataset",
            "name": "Attack 1 — Dataset File Tampering",
            "target": "Dataset Files & SHA-256 Digest",
            "expected_display": "DATA INTEGRITY FAILURE",
            "endpoint": "/api/demonstration/attack-1-dataset-tamper",
            "description": "Modifies test image on disk and verifies that composite hashing detects the discrepancy and logs a security event.",
        },
        {
            "id": "attack_2_model",
            "name": "Attack 2 — Model Weights Tampering",
            "target": "Model Weights Binary & Eligibility",
            "expected_display": "MODEL INTEGRITY FAILURE / INFERENCE BLOCKED",
            "endpoint": "/api/demonstration/attack-2-model-tamper",
            "description": "Alters model weights on disk post-approval and proves that pre-inference check blocks inference execution.",
        },
        {
            "id": "attack_3_inference",
            "name": "Attack 3 — Inference Output Tampering",
            "target": "Canonical Evidence JSON & Ed25519 Signature",
            "expected_display": "INFERENCE EVIDENCE INVALID",
            "endpoint": "/api/demonstration/attack-3-inference-tamper",
            "description": "Alters stored predictions and bounding boxes in database, proving that 5-pillar verification catches evidence mismatch.",
        },
        {
            "id": "attack_4_audit",
            "name": "Attack 4 — Cryptographic Audit Chain Tampering",
            "target": "Append-Only Hash Chain & Chronological Linkage",
            "expected_display": "AUDIT CHAIN INVALID",
            "endpoint": "/api/demonstration/attack-4-audit-tamper",
            "description": "Alters a historical audit event directly in the database and demonstrates that chain traversal detects broken linkage.",
        },
    ]