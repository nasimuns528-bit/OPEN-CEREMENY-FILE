"""
Pydantic schemas for Audit Event querying, details, and chain verification.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuditEventResponse(BaseModel):
    id: str
    actor_id: Optional[str] = None
    actor_username: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    version_tag: Optional[str] = None
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    details: Optional[str] = None
    ip_address: Optional[str] = None
    previous_event_hash: Optional[str] = None
    current_hash: str
    sequence_number: int
    created_at: datetime

    class Config:
        from_attributes = True


class AuditVerifyResponse(BaseModel):
    valid: bool
    events_checked: int
    first_invalid_event: Optional[str] = None
    tamper_details: Optional[str] = None
    chain_head_hash: Optional[str] = None
