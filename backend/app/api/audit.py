"""
Audit Trail API router for Phase 3 (Multi-Contributor Provenance).
Provides endpoints to inspect immutable audit events and verify the complete hash chain.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.audit import AuditEvent
from app.models.user import User
from app.schemas.audit import AuditEventResponse, AuditVerifyResponse
from app.security.dependencies import get_current_user, require_role
from app.services import audit_service

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get(
    "",
    response_model=List[AuditEventResponse],
    summary="Query audit events with pagination and filters",
)
async def list_audit_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    actor_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(AuditEvent).order_by(AuditEvent.sequence_number.desc())

    if action:
        query = query.where(AuditEvent.action == action)
    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type)
    if actor_id:
        query = query.where(AuditEvent.actor_id == actor_id)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    events = list(result.scalars().all())

    return [AuditEventResponse.from_orm(e) for e in events]


@router.post(
    "/verify",
    response_model=AuditVerifyResponse,
    summary="Cryptographically verify complete audit hash chain (Reviewer / Admin)",
)
async def verify_chain(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("REVIEWER", "ADMIN")),
):
    valid, checked, first_invalid_id, details, head_hash = (
        await audit_service.verify_audit_chain(db)
    )
    return AuditVerifyResponse(
        valid=valid,
        events_checked=checked,
        first_invalid_event=first_invalid_id,
        tamper_details=details,
        chain_head_hash=head_hash,
    )
