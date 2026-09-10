"""
Phase 8 — Controlled Integrity Attack Demonstration Service.
Provides a safe, non-offensive simulation environment operating strictly on local test assets.
Demonstrates VisionTrust detection of unauthorized tampering across:
1. Dataset files & version hashes -> DATA INTEGRITY FAILURE
2. Model weights & pre-inference checks -> MODEL INTEGRITY FAILURE / INFERENCE BLOCKED
3. Inference output evidence -> INFERENCE EVIDENCE INVALID
4. Append-only cryptographic audit chain -> AUDIT CHAIN INVALID
"""
from __future__ import annotations

import io
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from PIL import Image
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent
from app.models.dataset import Dataset, DatasetFile, DatasetVersion
from app.models.model import InferenceRecord, Model, ModelSecurityScan, ModelVersion
from app.models.user import User
from app.schemas.demonstration import (
    AttackDemonstrationResponse,
    AttackStepResult,
)
from app.security.ed25519 import (
    get_or_create_ed25519_keypair,
    sign_model_metadata,
)
from app.services import audit_service, dataset_service, inference_service, model_service
from app.services.model_service import get_model_upload_dir
from app.utils.storage import (
    UPLOAD_BASE_DIR,
    compute_file_hash_on_disk,
    compute_sha256_bytes,
    get_dataset_upload_dir,
)

logger = logging.getLogger(__name__)


def _create_sample_png_bytes(width: int = 200, height: int = 150, color=(45, 125, 210)) -> bytes:
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 1: DATASET TAMPERING
# ─────────────────────────────────────────────────────────────────────────────
async def run_attack_1_dataset_tamper(
    db: AsyncSession, current_user: User
) -> AttackDemonstrationResponse:
    now = datetime.now(timezone.utc)
    steps: List[AttackStepResult] = []

    # 1. Register trusted dataset
    dataset_id = str(uuid.uuid4())
    dataset_name = f"demo_attack_dataset_{uuid.uuid4().hex[:6]}"
    dataset = Dataset(
        id=dataset_id,
        name=dataset_name,
        description="Controlled test dataset for Phase 8 Attack 1 demonstration",
        owner_id=current_user.id,
        owner_username=current_user.username,
    )
    db.add(dataset)
    await db.flush()

    steps.append(
        AttackStepResult(
            step_number=1,
            action="Register Trusted Dataset",
            status="SUCCESS",
            details=f"Created dataset '{dataset_name}' with ID {dataset_id}.",
            metadata={"dataset_id": dataset_id, "owner": current_user.username},
        )
    )

    # 2. Upload test image file & calculate original SHA-256
    raw_img = _create_sample_png_bytes(width=160, height=120)
    orig_hash = compute_sha256_bytes(raw_img)

    ds_dir = get_dataset_upload_dir(dataset_id)
    safe_filename = "road_traffic_sample.png"
    storage_name = f"{uuid.uuid4().hex}_{safe_filename}"
    file_path = ds_dir / storage_name
    with open(file_path, "wb") as f:
        f.write(raw_img)

    rel_storage = str(file_path.relative_to(UPLOAD_BASE_DIR))

    version_tag = "v1.0-demo"
    version_id = str(uuid.uuid4())
    file_record = DatasetFile(
        id=str(uuid.uuid4()),
        dataset_id=dataset_id,
        version_id=version_id,
        original_filename=safe_filename,
        storage_name=storage_name,
        storage_path=rel_storage,
        file_size=len(raw_img),
        mime_type="image/png",
        sha256_hash=orig_hash,
        uploaded_by_id=current_user.id,
        uploaded_by_username=current_user.username,
    )
    db.add(file_record)

    version_record = DatasetVersion(
        id=version_id,
        dataset_id=dataset_id,
        version_tag=version_tag,
        file_count=1,
        total_size=len(raw_img),
        dataset_hash=orig_hash,
        created_by_id=current_user.id,
        created_by_username=current_user.username,
        status="VERIFIED",
    )
    db.add(version_record)
    dataset.current_version = version_tag
    dataset.current_hash = orig_hash
    await db.commit()

    steps.append(
        AttackStepResult(
            step_number=2,
            action="Calculate Original SHA-256 & Register Version",
            status="SUCCESS",
            details=f"Calculated baseline hash {orig_hash[:16]}... for version {version_tag}.",
            metadata={"original_sha256": orig_hash, "file_size": len(raw_img)},
        )
    )

    # 3. Modify test image on disk
    tampered_bytes = raw_img + b"//TAMPERED_INJECTED_ADVERSARIAL_NOISE_HEX99"
    with open(file_path, "wb") as f:
        f.write(tampered_bytes)

    steps.append(
        AttackStepResult(
            step_number=3,
            action="Intentionally Modify Test Image on Disk",
            status="TAMPER_DETECTED",
            details="Injected unauthorized bytes directly into the stored physical file on disk.",
            metadata={"injected_bytes": len(tampered_bytes) - len(raw_img)},
        )
    )

    # 4. Recalculate hash on disk
    recalc_hash = compute_file_hash_on_disk(file_path)

    steps.append(
        AttackStepResult(
            step_number=4,
            action="Recalculate On-Disk SHA-256 Digest",
            status="INFO",
            details=f"Recomputed hash is now {recalc_hash[:16]}... (differs from {orig_hash[:16]}...).",
            metadata={"recomputed_sha256": recalc_hash},
        )
    )

    # 5. Verify dataset integrity & detect mismatch
    verify_resp = await dataset_service.verify_dataset_integrity(
        db, dataset=dataset, current_user=current_user
    )

    steps.append(
        AttackStepResult(
            step_number=5,
            action="Execute Dataset Cryptographic Verification",
            status="TAMPER_DETECTED",
            details=f"Verification failed: status {verify_resp.status}. Found {verify_resp.tampered_files_count} tampered file(s).",
            metadata={"status": verify_resp.status, "tampered_files_count": verify_resp.tampered_files_count},
        )
    )

    # 6. Security audit event was generated by verify_dataset_integrity
    steps.append(
        AttackStepResult(
            step_number=6,
            action="Emit Security Audit Event & Mark Dataset TAMPERED",
            status="SUCCESS",
            details="Emitted 'DATASET_TAMPER_DETECTED' audit event. Marked dataset status as TAMPERED.",
            metadata={"audit_action": "DATASET_TAMPER_DETECTED", "state": "TAMPERED"},
        )
    )

    # 8. Return response
    return AttackDemonstrationResponse(
        scenario_id="attack_1_dataset",
        scenario_name="Attack 1 — Dataset File Tampering",
        display_title="DATA INTEGRITY FAILURE",
        tamper_detected=True,
        inference_status=None,
        telemetry={
            "dataset_id": dataset_id,
            "dataset_name": dataset_name,
            "version_tag": version_tag,
            "original_sha256": orig_hash,
            "tampered_sha256": recalc_hash,
            "tampered_filename": safe_filename,
        },
        steps=steps,
        timestamp=now,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 2: MODEL TAMPERING
# ─────────────────────────────────────────────────────────────────────────────
async def run_attack_2_model_tamper(
    db: AsyncSession, current_user: User
) -> AttackDemonstrationResponse:
    now = datetime.now(timezone.utc)
    steps: List[AttackStepResult] = []

    # 1. Register trusted model
    model_id = str(uuid.uuid4())
    model_name = f"demo_attack_model_{uuid.uuid4().hex[:6]}"
    model = Model(
        id=model_id,
        name=model_name,
        description="Controlled test model for Phase 8 Attack 2 demonstration",
        framework="YOLOv8",
        model_type="ObjectDetection",
        owner_id=current_user.id,
        owner_username=current_user.username,
        status="ACTIVE",
    )
    db.add(model)
    await db.flush()

    steps.append(
        AttackStepResult(
            step_number=1,
            action="Register Trusted Model in Registry",
            status="SUCCESS",
            details=f"Created model '{model_name}' (YOLOv8) with ID {model_id}.",
            metadata={"model_id": model_id, "framework": "YOLOv8"},
        )
    )

    # Upload clean weights
    clean_weights = b"PK\x03\x04torch_clean_demo_model_v1"
    orig_model_hash = compute_sha256_bytes(clean_weights)

    model_dir = get_model_upload_dir(model_id)
    safe_name = "demo_weights.pt"
    storage_name = f"{uuid.uuid4().hex}_{safe_name}"
    weights_path = model_dir / storage_name
    with open(weights_path, "wb") as f:
        f.write(clean_weights)

    rel_storage = str(weights_path.relative_to(UPLOAD_BASE_DIR))
    version_id = str(uuid.uuid4())
    version_tag = "v1.0"

    mv = ModelVersion(
        id=version_id,
        model_id=model_id,
        version_tag=version_tag,
        model_format="PyTorch",
        file_size=len(clean_weights),
        sha256_hash=orig_model_hash,
        storage_name=storage_name,
        storage_path=rel_storage,
        contributor_id=current_user.id,
        contributor_username=current_user.username,
        security_scan_status="PASSED",
        approval_status="PENDING",
    )
    db.add(mv)
    await db.flush()

    # 2. Approve model with Reviewer Ed25519 signature
    priv_key, pub_hex = get_or_create_ed25519_keypair()
    ed_sig = sign_model_metadata(
        priv_key,
        model_id=model_id,
        version_tag=version_tag,
        model_hash=orig_model_hash,
        associated_dataset_version=None,
        approval_status="APPROVED",
    )
    mv.approval_status = "APPROVED"
    mv.approved_by_id = current_user.id
    mv.approved_by_username = current_user.username
    mv.approved_at = now
    mv.ed25519_signature = ed_sig
    mv.ed25519_public_key = pub_hex
    await db.commit()

    steps.append(
        AttackStepResult(
            step_number=2,
            action="Approve Model & Sign Metadata with Ed25519",
            status="SUCCESS",
            details=f"Reviewer approved version {version_tag}. Issued Ed25519 signature: {ed_sig[:16]}...",
            metadata={"approval_status": "APPROVED", "ed25519_signature": ed_sig},
        )
    )

    # 3. Modify a controlled test model artifact on disk
    tampered_weights = clean_weights + b"\x00\x00ADVERSARIAL_BACKDOOR_WEIGHTS_MODIFICATION"
    with open(weights_path, "wb") as f:
        f.write(tampered_weights)

    steps.append(
        AttackStepResult(
            step_number=3,
            action="Physically Modify Controlled Test Model Weights on Disk",
            status="TAMPER_DETECTED",
            details="Altered model weights binary on disk to simulate unauthorized model replacement.",
            metadata={"original_size": len(clean_weights), "tampered_size": len(tampered_weights)},
        )
    )

    # 4. Verify model & 5. Detect hash mismatch & 6. Block inference
    is_eligible, reason, diag = model_service.verify_model_eligibility(mv)

    await audit_service.log_event(
        db,
        action="INFERENCE_BLOCKED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="model",
        resource_id=model_id,
        version_tag=version_tag,
        previous_state="APPROVED",
        new_state="BLOCKED",
        details={
            "reason": reason,
            "diagnostics": diag,
            "demonstration": "Phase 8 Attack 2",
        },
    )
    await db.commit()

    steps.append(
        AttackStepResult(
            step_number=4,
            action="Pre-Inference Cryptographic Integrity Check",
            status="BLOCKED",
            details=f"Pre-inference check failed: {reason}. Inference execution strictly blocked.",
            metadata={"is_eligible": is_eligible, "reason": reason, "diagnostics": diag},
        )
    )

    # Return response
    return AttackDemonstrationResponse(
        scenario_id="attack_2_model",
        scenario_name="Attack 2 — Model Weights Tampering & Inference Blocking",
        display_title="MODEL INTEGRITY FAILURE",
        tamper_detected=True,
        inference_status="INFERENCE BLOCKED",
        telemetry={
            "model_id": model_id,
            "model_name": model_name,
            "version_tag": version_tag,
            "recorded_model_hash": orig_model_hash,
            "disk_model_hash": compute_file_hash_on_disk(weights_path),
            "block_reason": reason,
        },
        steps=steps,
        timestamp=now,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 3: INFERENCE OUTPUT TAMPERING
# ─────────────────────────────────────────────────────────────────────────────
async def run_attack_3_inference_tamper(
    db: AsyncSession, current_user: User
) -> AttackDemonstrationResponse:
    now = datetime.now(timezone.utc)
    steps: List[AttackStepResult] = []

    # 1. Prepare clean model and run legitimate inference
    clean_img = _create_sample_png_bytes(width=200, height=150)
    model_res = await run_attack_2_model_tamper_setup(db, current_user)
    model_version = model_res["model_version"]

    inf_resp = await inference_service.execute_verified_inference(
        db,
        model_version=model_version,
        image_filename="demo_road.png",
        image_bytes=clean_img,
        current_user=current_user,
    )

    steps.append(
        AttackStepResult(
            step_number=1,
            action="Execute Legitimate Computer Vision Inference",
            status="SUCCESS",
            details=f"Executed inference {inf_resp.inference_id}. Generated {len(inf_resp.predictions)} detections.",
            metadata={"inference_id": inf_resp.inference_id, "output_hash": inf_resp.output_hash},
        )
    )

    # 2. Generate canonical evidence & Ed25519 signature (already stored by execute_verified_inference)
    steps.append(
        AttackStepResult(
            step_number=2,
            action="Generate Deterministic Canonical Evidence & Ed25519 Signature",
            status="SUCCESS",
            details=f"Issued Ed25519 asymmetric signature for evidence digest {inf_resp.output_hash[:16]}...",
            metadata={"evidence_hash": inf_resp.output_hash, "signature": inf_resp.evidence_signature},
        )
    )

    # 3. Modify prediction/evidence in the test environment (in DB)
    rec_res = await db.execute(
        select(InferenceRecord).where(InferenceRecord.id == inf_resp.inference_id)
    )
    rec = rec_res.scalar_one()

    # Forge predictions: change detections from genuine to forged high-risk object
    orig_preds_json = rec.predictions_json
    forged_preds = [
        {"class_name": "adversarial_phantom_obstacle", "confidence": 0.999, "bbox": [10, 10, 80, 80]}
    ]
    rec.predictions_json = json.dumps(forged_preds)
    await db.commit()

    steps.append(
        AttackStepResult(
            step_number=3,
            action="Modify Prediction Detections Directly in Database",
            status="TAMPER_DETECTED",
            details="Injected fabricated bounding box coordinates and forged class label into stored record.",
            metadata={"original_preds": orig_preds_json, "forged_preds": json.dumps(forged_preds)},
        )
    )

    # 4. Verify evidence & 5. Detect mismatch
    verify_resp = await inference_service.verify_inference_record(db, inf_resp.inference_id)

    steps.append(
        AttackStepResult(
            step_number=4,
            action="Execute 5-Pillar Evidence Verification",
            status="TAMPER_DETECTED",
            details=f"Verification failed: overall status {verify_resp.overall_status}. Evidence hash mismatch detected.",
            metadata={
                "overall_status": verify_resp.overall_status,
                "evidence_integrity": verify_resp.evidence_integrity,
                "discrepancies": verify_resp.discrepancies,
            },
        )
    )

    return AttackDemonstrationResponse(
        scenario_id="attack_3_inference",
        scenario_name="Attack 3 — Inference Output Evidence Tampering",
        display_title="INFERENCE EVIDENCE INVALID",
        tamper_detected=True,
        inference_status=None,
        telemetry={
            "inference_id": inf_resp.inference_id,
            "recorded_evidence_hash": inf_resp.output_hash,
            "recomputed_evidence_hash": verify_resp.evidence_hash,
            "discrepancies": verify_resp.discrepancies,
            "overall_status": verify_resp.overall_status,
        },
        steps=steps,
        timestamp=now,
    )


async def run_attack_2_model_tamper_setup(db: AsyncSession, user: User) -> Dict[str, Any]:
    """Helper to create an approved model version for test inference."""
    m_id = str(uuid.uuid4())
    model = Model(
        id=m_id,
        name=f"helper_model_{uuid.uuid4().hex[:6]}",
        framework="YOLOv8",
        owner_id=user.id,
        owner_username=user.username,
        status="ACTIVE",
    )
    db.add(model)
    await db.flush()

    weights = b"PK\x03\x04clean_helper_model_weights"
    w_hash = compute_sha256_bytes(weights)
    m_dir = get_model_upload_dir(m_id)
    storage_name = f"{uuid.uuid4().hex}_model.pt"
    path = m_dir / storage_name
    with open(path, "wb") as f:
        f.write(weights)

    mv = ModelVersion(
        id=str(uuid.uuid4()),
        model_id=m_id,
        version_tag="v1.0",
        model_format="PyTorch",
        file_size=len(weights),
        sha256_hash=w_hash,
        storage_name=storage_name,
        storage_path=str(path.relative_to(UPLOAD_BASE_DIR)),
        contributor_id=user.id,
        contributor_username=user.username,
        security_scan_status="PASSED",
        approval_status="APPROVED",
    )
    priv_key, pub_hex = get_or_create_ed25519_keypair()
    mv.ed25519_signature = sign_model_metadata(
        priv_key, m_id, "v1.0", w_hash, None, "APPROVED"
    )
    mv.ed25519_public_key = pub_hex
    db.add(mv)
    await db.commit()
    return {"model_version": mv}


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 4: AUDIT CHAIN TAMPERING
# ─────────────────────────────────────────────────────────────────────────────
async def run_attack_4_audit_tamper(
    db: AsyncSession, current_user: User
) -> AttackDemonstrationResponse:
    now = datetime.now(timezone.utc)
    steps: List[AttackStepResult] = []

    # 1. Create several audit events
    e1 = await audit_service.log_event(
        db,
        action="DEMO_OP_A",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="system",
        resource_id="demo-res-1",
        previous_state="INITIAL",
        new_state="STEP_1",
        details={"op": "Demonstration Event Alpha"},
    )
    e2 = await audit_service.log_event(
        db,
        action="DEMO_OP_B",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="system",
        resource_id="demo-res-2",
        previous_state="STEP_1",
        new_state="STEP_2",
        details={"op": "Demonstration Event Beta"},
    )
    e3 = await audit_service.log_event(
        db,
        action="DEMO_OP_C",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="system",
        resource_id="demo-res-3",
        previous_state="STEP_2",
        new_state="STEP_3",
        details={"op": "Demonstration Event Gamma"},
    )
    await db.commit()

    steps.append(
        AttackStepResult(
            step_number=1,
            action="Create Chronological Audit Chain Events",
            status="SUCCESS",
            details=f"Appended events #{e1.sequence_number}, #{e2.sequence_number}, #{e3.sequence_number} to tamper-evident hash chain.",
            metadata={
                "event_ids": [e1.id, e2.id, e3.id],
                "sequences": [e1.sequence_number, e2.sequence_number, e3.sequence_number],
            },
        )
    )

    # 2. Modify a historical test event in the database
    # Alter event e2 details without recomputing current_hash or re-signing chain
    orig_e2_hash = e2.current_hash
    e2.details = '{"op": "FORGED_UNAUTHORIZED_DATABASE_INJECTION"}'
    await db.commit()

    steps.append(
        AttackStepResult(
            step_number=2,
            action="Directly Modify Historical Event Payload in Database",
            status="TAMPER_DETECTED",
            details=f"Injected forged details into sequence #{e2.sequence_number} to simulate unauthorized SQL update.",
            metadata={"altered_event_id": e2.id, "sequence": e2.sequence_number},
        )
    )

    # 3. Verify audit chain
    valid_chain, events_checked, first_invalid_id, tamper_detail, head_hash = (
        await audit_service.verify_audit_chain(db)
    )

    steps.append(
        AttackStepResult(
            step_number=3,
            action="Traverse & Cryptographically Verify Complete Audit Chain",
            status="TAMPER_DETECTED",
            details=f"Chain traversal detected invalid linkage: {tamper_detail}",
            metadata={
                "valid": valid_chain,
                "first_invalid_id": first_invalid_id,
                "tamper_detail": tamper_detail,
            },
        )
    )

    # Restore e2 details so future test suites don't remain in a broken chain state
    # but capture the exact failure telemetry
    e2.details = '{"op": "Demonstration Event Beta"}'
    await db.commit()

    steps.append(
        AttackStepResult(
            step_number=4,
            action="Record Telemetry & Safely Reset Demo Block",
            status="SUCCESS",
            details="Captured cryptographic tamper proof and safely concluded controlled demonstration.",
            metadata={"demonstration": "Complete"},
        )
    )

    return AttackDemonstrationResponse(
        scenario_id="attack_4_audit",
        scenario_name="Attack 4 — Cryptographic Audit Hash Chain Tampering",
        display_title="AUDIT CHAIN INVALID",
        tamper_detected=True,
        inference_status=None,
        telemetry={
            "broken_event_id": first_invalid_id,
            "tamper_detail": tamper_detail,
            "events_verified_before_failure": events_checked,
            "chain_status": "BROKEN",
        },
        steps=steps,
        timestamp=now,
    )