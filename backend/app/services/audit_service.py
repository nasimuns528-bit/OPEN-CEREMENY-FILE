"""
Audit logging service with append-only tamper-evident hash chain.
Extended for Phase 3 Multi-Contributor Provenance tracking.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent

logger = logging.getLogger(__name__)

GENESIS_HASH = "GENESIS_BLOCK_HASH_VISIONTRUST_ROOT"


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def compute_audit_hash(
    event_id: str,
    actor_id: Optional[str],
    action: str,
    resource_type: Optional[str],
    resource_id: Optional[str],
    version_tag: Optional[str],
    previous_state: Optional[str],
    new_state: Optional[str],
    details: Optional[str],
    timestamp: str,
    previous_hash: Optional[str],
) -> str:
    """
    Compute canonical SHA-256 hash of all event fields for tamper detection.
    Guarantees deterministic serialization across all fields.
    """
    content = "|".join([
        event_id,
        actor_id or "",
        action,
        resource_type or "",
        resource_id or "",
        version_tag or "",
        previous_state or "",
        new_state or "",
        details or "",
        timestamp,
        previous_hash or GENESIS_HASH,
    ])
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


async def log_event(
    db: AsyncSession,
    *,
    action: str,
    actor_id: Optional[str] = None,
    actor_username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    version_tag: Optional[str] = None,
    previous_state: Optional[str] = None,
    new_state: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> AuditEvent:
    """
    Append a new audit event to the tamper-evident chain.
    The event is flushed to obtain sequence and hash for callers.
    """
    # Fetch the last event to get its hash and sequence number
    last_result = await db.execute(
        select(AuditEvent)
        .order_by(AuditEvent.sequence_number.desc())
        .limit(1)
    )
    last_event = last_result.scalar_one_or_none()

    previous_hash = last_event.current_hash if last_event else None
    next_seq = (last_event.sequence_number + 1) if last_event else 1

    import uuid
    event_id = str(uuid.uuid4())
    now = _utcnow().replace(microsecond=0)
    timestamp_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    details_str = json.dumps(details, sort_keys=True) if details else None

    current_hash = compute_audit_hash(
        event_id=event_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        version_tag=version_tag,
        previous_state=previous_state,
        new_state=new_state,
        details=details_str,
        timestamp=timestamp_str,
        previous_hash=previous_hash,
    )

    event = AuditEvent(
        id=event_id,
        actor_id=actor_id,
        actor_username=actor_username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        version_tag=version_tag,
        previous_state=previous_state,
        new_state=new_state,
        details=details_str,
        ip_address=ip_address,
        previous_event_hash=previous_hash,
        current_hash=current_hash,
        sequence_number=next_seq,
        created_at=now,
    )
    db.add(event)
    await db.flush()

    logger.info(
        "AUDIT seq=%d action=%s actor=%s resource=%s/%s state=(%s->%s)",
        next_seq, action, actor_username or actor_id, resource_type, resource_id, previous_state, new_state
    )
    return event


async def verify_audit_chain(db: AsyncSession) -> Tuple[bool, int, Optional[str], Optional[str], Optional[str]]:
    """
    Verify complete audit chain cryptographic integrity from genesis to head.
    Returns (valid, events_checked, first_invalid_event_id, tamper_details, head_hash).
    """
    result = await db.execute(
        select(AuditEvent).order_by(AuditEvent.sequence_number.asc())
    )
    events = list(result.scalars().all())

    if not events:
        return True, 0, None, None, None

    expected_previous_hash: Optional[str] = None

    for idx, event in enumerate(events):
        # 1. Verify previous hash linkage
        if idx == 0:
            # First event: previous_event_hash should be None or GENESIS_HASH
            if event.previous_event_hash is not None and event.previous_event_hash != GENESIS_HASH:
                return (
                    False,
                    idx + 1,
                    event.id,
                    f"First event sequence #{event.sequence_number} previous hash invalid: {event.previous_event_hash}",
                    None,
                )
        else:
            if event.previous_event_hash != expected_previous_hash:
                return (
                    False,
                    idx + 1,
                    event.id,
                    f"Broken linkage at sequence #{event.sequence_number}: expected previous hash {expected_previous_hash}, found {event.previous_event_hash}",
                    None,
                )

        # 2. Verify self-hash integrity
        # Use stored created_at timestamp in canonical ISO format
        timestamp_str = event.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if event.created_at else ""
        computed_hash = compute_audit_hash(
            event_id=event.id,
            actor_id=event.actor_id,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            version_tag=event.version_tag,
            previous_state=event.previous_state,
            new_state=event.new_state,
            details=event.details,
            timestamp=timestamp_str,
            previous_hash=event.previous_event_hash,
        )

        if computed_hash != event.current_hash:
            return (
                False,
                idx + 1,
                event.id,
                f"Hash mismatch at sequence #{event.sequence_number}: expected {computed_hash}, stored {event.current_hash}",
                None,
            )

        expected_previous_hash = event.current_hash

    return True, len(events), None, None, events[-1].current_hash
