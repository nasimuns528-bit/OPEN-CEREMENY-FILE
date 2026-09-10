"""
Dataset, DatasetVersion, and DatasetFile models for Phase 2.
Enforces cryptographic integrity tracking and provenance.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DatasetStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    VERIFIED = "VERIFIED"
    TAMPERED = "TAMPERED"
    ARCHIVED = "ARCHIVED"


class Dataset(Base):
    __tablename__ = "datasets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Contributor tracking
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    owner_username: Mapped[str] = mapped_column(String(64), nullable=False)

    # Current integrity status
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=DatasetStatus.ACTIVE.value)

    # Latest version tag (e.g. "v1", "v2") and hash
    current_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    current_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, onupdate=func.now()
    )

    # Relationships
    versions: Mapped[list[DatasetVersion]] = relationship(
        "DatasetVersion", back_populates="dataset", cascade="all, delete-orphan", order_by="DatasetVersion.created_at.desc()"
    )
    files: Mapped[list[DatasetFile]] = relationship(
        "DatasetFile", back_populates="dataset", cascade="all, delete-orphan"
    )


class DatasetVersion(Base):
    __tablename__ = "dataset_versions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    dataset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_tag: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g., "v1", "v2"
    file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    # Cryptographic composite hash of all files in this version
    dataset_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    created_by_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_by_username: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default=DatasetStatus.ACTIVE.value)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    dataset: Mapped[Dataset] = relationship("Dataset", back_populates="versions")
    files: Mapped[list[DatasetFile]] = relationship("DatasetFile", back_populates="version")


class DatasetFile(Base):
    __tablename__ = "dataset_files"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    dataset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("dataset_versions.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # File identification & safe storage
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_name: Mapped[str] = mapped_column(String(255), nullable=False)  # Unique server-side name
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)  # Relative to upload root

    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)

    # Cryptographic SHA-256 hash of file content
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    uploaded_by_id: Mapped[str] = mapped_column(String(36), nullable=False)
    uploaded_by_username: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    dataset: Mapped[Dataset] = relationship("Dataset", back_populates="files")
    version: Mapped[DatasetVersion | None] = relationship("DatasetVersion", back_populates="files")
