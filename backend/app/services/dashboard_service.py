"""
Trust Dashboard and Integrity Assurance Scoring service.
Computes a transparent 0-100 Integrity Assurance Score across 6 operational pillars:
1. Data Integrity (20 pts)
2. Model Integrity (20 pts)
3. Provenance Chain (15 pts)
4. Contributor Trust (15 pts)
5. Inference Evidence (15 pts)
6. Security Scanning (15 pts)

Includes explicit disclaimer that assurance scores assess pipeline provenance and cryptographic
integrity, not mathematical proof of AI model correctness.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dataset import Dataset, DatasetVersion
from app.models.model import (
    InferenceRecord,
    Model,
    ModelSecurityScan,
    ModelVersion,
)
from app.models.user import User
from app.schemas.dashboard import (
    ScoringComponent,
    SecurityAlertItem,
    TrustMetricsResponse,
)
from app.services.audit_service import verify_audit_chain

logger = logging.getLogger(__name__)


async def get_trust_metrics(db: AsyncSession) -> TrustMetricsResponse:
    now = datetime.now(timezone.utc)
    alerts: List[SecurityAlertItem] = []

    # 1. DATA INTEGRITY (20 points)
    ds_res = await db.execute(select(Dataset))
    all_datasets = list(ds_res.scalars().all())

    dv_res = await db.execute(select(DatasetVersion))
    all_versions = list(dv_res.scalars().all())

    total_dv = len(all_versions)
    verified_dv = 0
    tampered_dv = 0

    for dv in all_versions:
        if getattr(dv, "status", None) == "TAMPERED":
            tampered_dv += 1
            alerts.append(
                SecurityAlertItem(
                    id=str(uuid.uuid4()),
                    severity="CRITICAL",
                    category="DATASET",
                    title="Dataset Version Tampered",
                    description=f"Dataset version {dv.version_tag} has detected hash or file integrity tampering.",
                    timestamp=dv.created_at or now,
                )
            )
        else:
            verified_dv += 1

    if total_dv == 0:
        data_score = 20.0
        data_status = "OPTIMAL"
        data_explanation = "No dataset versions registered yet. Baseline integrity intact."
    else:
        ratio = verified_dv / total_dv
        data_score = round(ratio * 20.0, 1)
        if tampered_dv > 0:
            data_status = "DEGRADED"
            data_explanation = f"{tampered_dv} of {total_dv} dataset versions compromised."
        else:
            data_status = "OPTIMAL"
            data_explanation = f"All {total_dv} dataset versions cryptographically verified."

    # 2. MODEL INTEGRITY (20 points)
    m_res = await db.execute(select(Model))
    all_models = list(m_res.scalars().all())

    mv_res = await db.execute(select(ModelVersion))
    all_mv = list(mv_res.scalars().all())

    total_mv = len(all_mv)
    approved_mv = 0
    pending_mv = 0
    rejected_mv = 0

    for mv in all_mv:
        if mv.approval_status == "APPROVED":
            approved_mv += 1
        elif mv.approval_status == "REJECTED":
            rejected_mv += 1
            alerts.append(
                SecurityAlertItem(
                    id=str(uuid.uuid4()),
                    severity="HIGH",
                    category="MODEL",
                    title="Model Version Rejected",
                    description=f"Model version {mv.version_tag} was rejected during security or reviewer inspection.",
                    timestamp=mv.created_at or now,
                )
            )
        else:
            pending_mv += 1

    if total_mv == 0:
        model_score = 20.0
        model_status = "OPTIMAL"
        model_explanation = "No model versions registered yet. Baseline integrity intact."
    else:
        ratio = approved_mv / total_mv
        model_score = round(ratio * 20.0, 1)
        if rejected_mv > 0:
            model_status = "DEGRADED"
            model_explanation = f"{rejected_mv} model versions rejected or untrusted."
        elif pending_mv > 0:
            model_status = "ATTENTION"
            model_explanation = f"{pending_mv} model versions awaiting reviewer verification."
        else:
            model_status = "OPTIMAL"
            model_explanation = f"All {approved_mv} model versions verified and approved."

    # 3. PROVENANCE CHAIN (15 points)
    valid_chain, events_checked, first_invalid_id, tamper_detail, head_hash = (
        await verify_audit_chain(db)
    )

    if valid_chain:
        prov_score = 15.0
        prov_status = "OPTIMAL"
        prov_explanation = f"Audit hash chain intact across {events_checked} chronological events."
    else:
        prov_score = 0.0
        prov_status = "DEGRADED"
        prov_explanation = f"Audit chain broken at event #{first_invalid_id}: {tamper_detail}"
        alerts.append(
            SecurityAlertItem(
                id=str(uuid.uuid4()),
                severity="CRITICAL",
                category="AUDIT",
                title="Cryptographic Audit Chain Broken",
                description=f"Provenance chain integrity failure: {tamper_detail}",
                timestamp=now,
            )
        )

    # 4. CONTRIBUTOR TRUST (15 points)
    u_res = await db.execute(select(User))
    all_users = list(u_res.scalars().all())

    total_users = len(all_users)
    active_users = sum(1 for u in all_users if u.is_active)
    inactive_users = total_users - active_users

    if total_users == 0:
        contrib_score = 15.0
        contrib_status = "OPTIMAL"
        contrib_explanation = "Default contributor posture intact."
    else:
        ratio = active_users / total_users
        contrib_score = round(ratio * 15.0, 1)
        if inactive_users > 0:
            contrib_status = "ATTENTION"
            contrib_explanation = f"{inactive_users} inactive/suspended contributor account(s)."
        else:
            contrib_status = "OPTIMAL"
            contrib_explanation = f"All {active_users} contributor accounts active with role-based policies."

    # 5. INFERENCE EVIDENCE (15 points)
    inf_res = await db.execute(select(InferenceRecord))
    all_inf = list(inf_res.scalars().all())

    total_inf = len(all_inf)
    verified_inf = sum(1 for r in all_inf if r.verification_status in ("VERIFIED", "Integrity verified"))
    tampered_inf = sum(1 for r in all_inf if r.verification_status == "TAMPERED")
    avg_conf = (
        sum(r.highest_confidence for r in all_inf) / total_inf if total_inf > 0 else 0.0
    )

    if total_inf == 0:
        inf_score = 15.0
        inf_status = "OPTIMAL"
        inf_explanation = "No inference executions logged yet. Pipeline ready."
    else:
        ratio = verified_inf / total_inf
        inf_score = round(ratio * 15.0, 1)
        if tampered_inf > 0:
            inf_status = "DEGRADED"
            inf_explanation = f"{tampered_inf} inference evidence records detected as tampered."
            alerts.append(
                SecurityAlertItem(
                    id=str(uuid.uuid4()),
                    severity="CRITICAL",
                    category="INFERENCE",
                    title="Inference Output Tampering Detected",
                    description=f"{tampered_inf} inference execution record(s) failed cryptographic evidence verification.",
                    timestamp=now,
                )
            )
        else:
            inf_status = "OPTIMAL"
            inf_explanation = f"All {total_inf} inference records cryptographically verified with Ed25519 signatures."

    # 6. SECURITY SCANNING (15 points)
    scan_res = await db.execute(select(ModelSecurityScan))
    all_scans = list(scan_res.scalars().all())

    total_scans = len(all_scans)
    clean_scans = sum(1 for s in all_scans if getattr(s, "scan_result", None) == "CLEAN")
    flagged_scans = sum(
        1 for s in all_scans if getattr(s, "scan_result", None) in ("FAILED", "FLAGGED", "MANUAL_REVIEW_REQUIRED")
    )

    if total_scans == 0:
        scan_score = 15.0
        scan_status = "OPTIMAL"
        scan_explanation = "No model scans executed yet."
    else:
        ratio = clean_scans / total_scans
        scan_score = round(ratio * 15.0, 1)
        if flagged_scans > 0:
            scan_status = "DEGRADED"
            scan_explanation = f"{flagged_scans} security scan(s) identified potential security threats."
            alerts.append(
                SecurityAlertItem(
                    id=str(uuid.uuid4()),
                    severity="HIGH",
                    category="MODEL",
                    title="Model Security Scan Alert",
                    description=f"{flagged_scans} model artifact(s) flagged for unsafe opcodes or forbidden imports.",
                    timestamp=now,
                )
            )
        else:
            scan_status = "OPTIMAL"
            scan_explanation = f"All {total_scans} model scans passed static bytecode inspection."

    # AGGREGATE ASSURANCE SCORE
    raw_total = data_score + model_score + prov_score + contrib_score + inf_score + scan_score
    assurance_score = round(min(100.0, max(0.0, raw_total)), 1)

    if assurance_score >= 85.0:
        rating = "HIGH ASSURANCE"
    elif assurance_score >= 60.0:
        rating = "MODERATE ASSURANCE"
    else:
        rating = "COMPROMISED"

    components = [
        ScoringComponent(
            key="data_integrity",
            name="Data Integrity",
            score=data_score,
            max_score=20.0,
            status=data_status,
            explanation=data_explanation,
            details={"total_versions": total_dv, "tampered_count": tampered_dv},
        ),
        ScoringComponent(
            key="model_integrity",
            name="Model Integrity",
            score=model_score,
            max_score=20.0,
            status=model_status,
            explanation=model_explanation,
            details={"total_models": total_mv, "approved_count": approved_mv, "rejected_count": rejected_mv},
        ),
        ScoringComponent(
            key="provenance_chain",
            name="Provenance Chain",
            score=prov_score,
            max_score=15.0,
            status=prov_status,
            explanation=prov_explanation,
            details={"events_checked": events_checked, "chain_valid": valid_chain},
        ),
        ScoringComponent(
            key="contributor_trust",
            name="Contributor Trust",
            score=contrib_score,
            max_score=15.0,
            status=contrib_status,
            explanation=contrib_explanation,
            details={"total_users": total_users, "active_users": active_users},
        ),
        ScoringComponent(
            key="inference_evidence",
            name="Inference Evidence",
            score=inf_score,
            max_score=15.0,
            status=inf_status,
            explanation=inf_explanation,
            details={"total_inferences": total_inf, "verified_count": verified_inf},
        ),
        ScoringComponent(
            key="security_scanning",
            name="Security Scanning",
            score=scan_score,
            max_score=15.0,
            status=scan_status,
            explanation=scan_explanation,
            details={"total_scans": total_scans, "flagged_count": flagged_scans},
        ),
    ]

    return TrustMetricsResponse(
        assurance_score=assurance_score,
        label="Integrity Assurance Score",
        rating=rating,
        disclaimer=(
            "Integrity assurance metrics measure system provenance, cryptographic hash consistency, "
            "and security scanning; not mathematical proof of AI correctness."
        ),
        scoring_breakdown=components,
        datasets_summary={
            "total_datasets": len(all_datasets),
            "total_versions": total_dv,
            "verified_count": verified_dv,
            "tampered_count": tampered_dv,
        },
        models_summary={
            "total_models": len(all_models),
            "total_versions": total_mv,
            "approved_count": approved_mv,
            "pending_count": pending_mv,
            "rejected_count": rejected_mv,
        },
        inference_summary={
            "total_inferences": total_inf,
            "verified_count": verified_inf,
            "tampered_count": tampered_inf,
            "avg_confidence": round(avg_conf, 3),
        },
        audit_chain_status={
            "chain_length": events_checked,
            "is_valid": valid_chain,
            "head_hash": head_hash,
            "tamper_detail": tamper_detail,
        },
        active_alerts_count=len(alerts),
        security_alerts=alerts,
        generated_at=now,
    )