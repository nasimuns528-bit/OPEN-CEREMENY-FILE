"""
Append-only AuditEvent model.
Every important security-sensitive action in the system creates an audit event.
Each event is chained to the previous one via SHA-256 hashing to detect tampering.
Extended for Phase 3 Multi-Contributor Provenance tracking.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # Who performed the action (user ID or "system")
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # What happened (e.g., DATASET_CREATED, FILE_UPLOADED, DATASET_VERIFIED, DATASET_TAMPER_DETECTED)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    # What resource was affected
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)  # e.g., "dataset", "file", "model"
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    # Phase 3 Provenance: asset version and state transition tracking
    version_tag: Mapped[str | None] = mapped_column(String(32), nullable=True)
    previous_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Additional metadata context (JSON string, no PII)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Network context
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Cryptographic Hash Chain Linkage:
    # current_hash = SHA-256( id | actor_id | action | resource_type | resource_id | version_tag | previous_state | new_state | details | timestamp | previous_hash )
    previous_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Monotonic sequence for tamper-evident ordering
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditEvent id={self.id!r} action={self.action!r} seq={self.sequence_number}>"
