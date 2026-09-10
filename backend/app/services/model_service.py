"""
Computer Vision Model Registry service for Phase 4.
Handles:
- Model cataloging and versioning
- File persistence, SHA-256 hashing, and static ModelScan inspection
- Ed25519 asymmetric cryptographic signing for reviewer approval
- 5-step strict eligibility verification before inference
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import BinaryIO, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.model import (
    Model,
    ModelApprovalStatus,
    ModelScanStatus,
    ModelSecurityScan,
    ModelStatus,
    ModelVersion,
)
from app.models.user import User
from app.security.ed25519 import (
    get_or_create_ed25519_keypair,
    sign_model_metadata,
    verify_model_metadata,
)
from app.security.model_scanner import scan_model_file
from app.services.audit_service import log_event
from app.utils.storage import (
    UPLOAD_BASE_DIR,
    compute_file_hash_on_disk,
    compute_sha256_stream,
    sanitize_filename,
)

logger = logging.getLogger(__name__)

ALLOWED_MODEL_EXTENSIONS = {".pt", ".onnx", ".bin", ".weights", ".safetensors"}
MAX_MODEL_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB limit


def get_model_upload_dir(model_id: str) -> Path:
    target_dir = UPLOAD_BASE_DIR / "models" / model_id
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir


async def create_model(
    db: AsyncSession,
    *,
    name: str,
    description: Optional[str],
    framework: str,
    model_type: str,
    current_user: User,
    ip_address: Optional[str] = None,
) -> Model:
    """Create a new model catalog entry."""
    model = Model(
        name=name.strip(),
        description=description.strip() if description else None,
        framework=framework.strip(),
        model_type=model_type.strip(),
        owner_id=current_user.id,
        owner_username=current_user.username,
        status=ModelStatus.ACTIVE.value,
    )
    db.add(model)
    await db.flush()

    await log_event(
        db,
        action="MODEL_CREATED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="model",
        resource_id=model.id,
        previous_state=None,
        new_state=ModelStatus.ACTIVE.value,
        details={"name": model.name, "framework": framework},
        ip_address=ip_address,
    )
    return model


async def get_model(
    db: AsyncSession,
    model_id: str,
    include_versions: bool = True,
) -> Optional[Model]:
    """Retrieve model by ID with optional eager loading of versions and scans."""
    query = select(Model).where(Model.id == model_id)
    if include_versions:
        query = query.options(
            selectinload(Model.versions).selectinload(ModelVersion.scans)
        )
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def list_models(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
) -> List[Model]:
    """List all models ordered by creation date descending."""
    result = await db.execute(
        select(Model)
        .options(selectinload(Model.versions))
        .order_by(Model.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return list(result.scalars().all())


async def upload_model_version(
    db: AsyncSession,
    *,
    model: Model,
    version_tag: str,
    original_filename: str,
    stream: BinaryIO,
    associated_dataset_version: Optional[str],
    current_user: User,
    ip_address: Optional[str] = None,
) -> ModelVersion:
    """
    Save model weights file, calculate SHA-256, run static security scan,
    and register model version.
    """
    ext = Path(original_filename).suffix.lower()
    if ext not in ALLOWED_MODEL_EXTENSIONS:
        raise ValueError(
            f"Model format '{ext}' is forbidden. Allowed: {sorted(ALLOWED_MODEL_EXTENSIONS)}"
        )

    safe_orig = sanitize_filename(original_filename)
    sha256_hash, file_size = compute_sha256_stream(stream)
    if file_size > MAX_MODEL_SIZE_BYTES:
        raise ValueError(f"Model file size {file_size} exceeds limit of {MAX_MODEL_SIZE_BYTES} bytes.")

    import uuid
    storage_name = f"{uuid.uuid4().hex}_{safe_orig}"
    model_dir = get_model_upload_dir(model.id)
    dest_path = model_dir / storage_name

    stream.seek(0)
    with open(dest_path, "wb") as f:
        while chunk := stream.read(65536):
            f.write(chunk)

    rel_storage_path = str(dest_path.relative_to(UPLOAD_BASE_DIR))

    # Run static security inspection
    scan_status, findings = scan_model_file(dest_path)

    mv = ModelVersion(
        model_id=model.id,
        version_tag=version_tag.strip(),
        model_format=ext,
        file_size=file_size,
        sha256_hash=sha256_hash,
        storage_name=storage_name,
        storage_path=rel_storage_path,
        contributor_id=current_user.id,
        contributor_username=current_user.username,
        associated_dataset_version=associated_dataset_version.strip() if associated_dataset_version else None,
        security_scan_status=scan_status,
        approval_status=ModelApprovalStatus.PENDING.value,
    )
    db.add(mv)
    await db.flush()

    scan_rec = ModelSecurityScan(
        model_version_id=mv.id,
        scanner_name="ModelSecurityScanner/StaticOpcode",
        scan_result=scan_status,
        findings_json=json.dumps(findings),
    )
    db.add(scan_rec)
    await db.flush()

    await log_event(
        db,
        action="MODEL_UPLOADED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="model",
        resource_id=model.id,
        version_tag=mv.version_tag,
        previous_state=None,
        new_state="PENDING",
        details={
            "version_tag": mv.version_tag,
            "sha256_hash": sha256_hash,
            "security_scan_status": scan_status,
            "findings_count": len(findings),
        },
        ip_address=ip_address,
    )
    return mv


async def approve_model_version(
    db: AsyncSession,
    *,
    model_version: ModelVersion,
    current_user: User,
    ip_address: Optional[str] = None,
) -> ModelVersion:
    """
    Reviewer approval workflow:
    - Verifies security scan status is PASSED (rejects FLAGGED or MANUAL_REVIEW_REQUIRED)
    - Signs canonical metadata using Ed25519 private key
    - Updates approval_status to APPROVED
    - Logs MODEL_VERIFIED audit event
    """
    if model_version.security_scan_status != ModelScanStatus.PASSED.value:
        raise ValueError(
            f"Cannot approve model version with security scan status: {model_version.security_scan_status}. "
            "Only PASSED models can be approved for inference."
        )

    priv_key, pub_key_hex = get_or_create_ed25519_keypair()
    signature_hex = sign_model_metadata(
        private_key=priv_key,
        model_id=model_version.model_id,
        version_tag=model_version.version_tag,
        model_hash=model_version.sha256_hash,
        associated_dataset_version=model_version.associated_dataset_version,
        approval_status=ModelApprovalStatus.APPROVED.value,
    )

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    previous_state = model_version.approval_status
    model_version.approval_status = ModelApprovalStatus.APPROVED.value
    model_version.approved_by_id = current_user.id
    model_version.approved_by_username = current_user.username
    model_version.approved_at = now
    model_version.ed25519_signature = signature_hex
    model_version.ed25519_public_key = pub_key_hex
    await db.flush()

    await log_event(
        db,
        action="MODEL_VERIFIED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="model",
        resource_id=model_version.model_id,
        version_tag=model_version.version_tag,
        previous_state=previous_state,
        new_state=ModelApprovalStatus.APPROVED.value,
        details={
            "approved_by": current_user.username,
            "ed25519_signature": signature_hex[:16] + "...",
            "model_hash": model_version.sha256_hash,
        },
        ip_address=ip_address,
    )
    return model_version


def verify_model_eligibility(
    model_version: ModelVersion,
) -> Tuple[bool, str, dict]:
    """
    Strict 5-step verification before a model can be used for inference:
    1. Verify file exists on disk
    2. Verify disk hash matches stored model SHA-256
    3. Verify security scan status is PASSED
    4. Verify approval status is APPROVED
    5. Verify Ed25519 digital signature
    Returns (is_eligible, failure_reason, diagnostics_dict).
    """
    diagnostics = {
        "file_exists": False,
        "hash_match": False,
        "scan_passed": False,
        "approved": False,
        "signature_valid": False,
    }

    disk_path = UPLOAD_BASE_DIR / model_version.storage_path
    if not disk_path.exists():
        return False, "Model file not found on disk storage.", diagnostics
    diagnostics["file_exists"] = True

    # 1. Verify physical file hash
    current_hash = compute_file_hash_on_disk(disk_path)
    if current_hash != model_version.sha256_hash:
        return (
            False,
            f"Model integrity tampered! Expected hash {model_version.sha256_hash}, current disk hash {current_hash}.",
            diagnostics,
        )
    diagnostics["hash_match"] = True

    # 2. Verify security scan status
    if model_version.security_scan_status != ModelScanStatus.PASSED.value:
        return (
            False,
            f"Security scan status is {model_version.security_scan_status} (must be PASSED).",
            diagnostics,
        )
    diagnostics["scan_passed"] = True

    # 3. Verify approval status
    if model_version.approval_status != ModelApprovalStatus.APPROVED.value:
        return (
            False,
            f"Model is not approved (current status: {model_version.approval_status}).",
            diagnostics,
        )
    diagnostics["approved"] = True

    # 4. Verify Ed25519 signature
    if not model_version.ed25519_signature or not model_version.ed25519_public_key:
        return False, "Model is missing required cryptographic signature material.", diagnostics

    sig_ok = verify_model_metadata(
        public_key_hex=model_version.ed25519_public_key,
        model_id=model_version.model_id,
        version_tag=model_version.version_tag,
        model_hash=model_version.sha256_hash,
        associated_dataset_version=model_version.associated_dataset_version,
        approval_status=model_version.approval_status,
        signature_hex=model_version.ed25519_signature,
    )
    if not sig_ok:
        return False, "Ed25519 signature verification failed! Metadata or keys have been modified.", diagnostics

    diagnostics["signature_valid"] = True
    return True, "Model passed all integrity and approval checks.", diagnostics
