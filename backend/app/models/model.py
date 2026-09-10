"""
Computer Vision Model Registry and Inference Record models for Phase 4 & Phase 5.
Supports:
- Model and ModelVersion tracking with associated dataset provenance
- Static security scan results (ModelScan / Opcode inspector)
- Ed25519 digital signatures for approved model versions
- Evidence-backed inference records with input/model/output cryptographic hashes
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ModelStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class ModelScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    PASSED = "PASSED"
    FLAGGED = "FLAGGED"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


class ModelApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class Model(Base):
    __tablename__ = "models"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False, default="YOLOv8")
    model_type: Mapped[str] = mapped_column(String(64), nullable=False, default="object_detection")

    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    owner_username: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default=ModelStatus.ACTIVE.value)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, onupdate=func.now()
    )

    versions: Mapped[list[ModelVersion]] = relationship(
        "ModelVersion", back_populates="model", cascade="all, delete-orphan", order_by="ModelVersion.created_at.desc()"
    )


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    model_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("models.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_tag: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g., "v1.0"
    model_format: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g., ".pt", ".onnx"
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Cryptographic SHA-256 hash of model file
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    storage_name: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)

    contributor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    contributor_username: Mapped[str] = mapped_column(String(64), nullable=False)

    # Provenance linkage to training/eval dataset version
    associated_dataset_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Security scan status
    security_scan_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ModelScanStatus.PENDING.value
    )

    # Reviewer approval status
    approval_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ModelApprovalStatus.PENDING.value
    )
    approved_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Asymmetric Cryptographic Signature (Ed25519)
    ed25519_signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ed25519_public_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    model: Mapped[Model] = relationship("Model", back_populates="versions")
    scans: Mapped[list[ModelSecurityScan]] = relationship(
        "ModelSecurityScan", back_populates="version", cascade="all, delete-orphan"
    )


class ModelSecurityScan(Base):
    __tablename__ = "model_security_scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    model_version_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("model_versions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scanner_name: Mapped[str] = mapped_column(String(64), nullable=False, default="ModelSecurityScanner/StaticOpcode")
    scan_result: Mapped[str] = mapped_column(String(32), nullable=False)  # "CLEAN", "FLAGGED", "MANUAL_REVIEW_REQUIRED"
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array of findings
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    version: Mapped[ModelVersion] = relationship("ModelVersion", back_populates="scans")


class InferenceRecord(Base):
    __tablename__ = "inference_records"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    input_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    input_storage_path: Mapped[str] = mapped_column(String(512), nullable=False)

    # Cryptographic digests of input and model used
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    model_version_id: Mapped[str] = mapped_column(String(36), nullable=False)
    model_version_tag: Mapped[str] = mapped_column(String(32), nullable=False)
    model_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Inference output predictions and confidence
    predictions_json: Mapped[str] = mapped_column(Text, nullable=False)  # Bounding boxes, labels, confidence
    highest_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Output integrity digest & Ed25519 signed evidence record
    output_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signing_algorithm: Mapped[str | None] = mapped_column(String(32), nullable=True, default="Ed25519")
    public_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Verification status: VERIFIED, MODEL_TAMPERED, UNAPPROVED_MODEL
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False, default="VERIFIED")

    executor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    executor_username: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
