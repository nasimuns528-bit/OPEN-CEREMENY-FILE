"""
Dataset integrity and provenance service for Phase 2 & Phase 3.
Implements:
- Safe file persistence and SHA-256 calculation
- Deterministic composite dataset hashing
- Disk-level cryptographic integrity verification and tamper detection
- Comprehensive audit event logging with state transitions
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import BinaryIO, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.dataset import Dataset, DatasetFile, DatasetStatus, DatasetVersion
from app.models.user import User
from app.schemas.dataset import (
    DatasetVerifyResponse,
    FileVerificationResult,
)
from app.services.audit_service import log_event
from app.utils.storage import (
    UPLOAD_BASE_DIR,
    compute_file_hash_on_disk,
    extract_safe_zip,
    sanitize_filename,
    save_upload_stream,
)

logger = logging.getLogger(__name__)


def compute_composite_dataset_hash(files: List[DatasetFile]) -> str:
    """
    Computes a deterministic composite SHA-256 hash for a dataset version:
    1. Sort files lexicographically by original_filename.
    2. Format each entry as: '{sha256_hash}:{file_size}:{original_filename}'.
    3. Compute SHA-256 over newline-separated entries.
    """
    if not files:
        return hashlib.sha256(b"EMPTY_DATASET_VERSION_ROOT").hexdigest()

    sorted_files = sorted(files, key=lambda f: f.original_filename)
    entries = [
        f"{f.sha256_hash}:{f.file_size}:{f.original_filename}"
        for f in sorted_files
    ]
    raw_payload = "\n".join(entries).encode("utf-8")
    return hashlib.sha256(raw_payload).hexdigest()


async def create_dataset(
    db: AsyncSession,
    *,
    name: str,
    description: Optional[str],
    current_user: User,
    ip_address: Optional[str] = None,
) -> Dataset:
    """Create a new dataset and emit DATASET_CREATED audit event."""
    dataset = Dataset(
        name=name.strip(),
        description=description.strip() if description else None,
        owner_id=current_user.id,
        owner_username=current_user.username,
        status=DatasetStatus.ACTIVE.value,
    )
    db.add(dataset)
    await db.flush()

    await log_event(
        db,
        action="DATASET_CREATED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="dataset",
        resource_id=dataset.id,
        previous_state=None,
        new_state=DatasetStatus.ACTIVE.value,
        details={"name": dataset.name},
        ip_address=ip_address,
    )
    return dataset


async def get_dataset(
    db: AsyncSession,
    dataset_id: str,
    include_files: bool = True,
) -> Optional[Dataset]:
    """Retrieve dataset by ID with optional eager loading of files and versions."""
    query = select(Dataset).where(Dataset.id == dataset_id)
    if include_files:
        query = query.options(
            selectinload(Dataset.files),
            selectinload(Dataset.versions),
        )
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def list_datasets(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
) -> List[Dataset]:
    """List datasets ordered by creation date descending."""
    result = await db.execute(
        select(Dataset)
        .options(selectinload(Dataset.files))
        .order_by(Dataset.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return list(result.scalars().all())


async def upload_file_to_dataset(
    db: AsyncSession,
    *,
    dataset: Dataset,
    original_filename: str,
    stream: BinaryIO,
    current_user: User,
    mime_type: str = "application/octet-stream",
    ip_address: Optional[str] = None,
) -> DatasetFile:
    """Save an uploaded file safely, compute SHA-256, record file, and emit audit event."""
    storage_name, storage_path, file_size, sha256_hash = save_upload_stream(
        dataset_id=dataset.id,
        original_filename=original_filename,
        stream=stream,
    )

    safe_orig = sanitize_filename(original_filename)

    dataset_file = DatasetFile(
        dataset_id=dataset.id,
        original_filename=safe_orig,
        storage_name=storage_name,
        storage_path=storage_path,
        file_size=file_size,
        mime_type=mime_type,
        sha256_hash=sha256_hash,
        uploaded_by_id=current_user.id,
        uploaded_by_username=current_user.username,
    )
    db.add(dataset_file)
    await db.flush()

    await log_event(
        db,
        action="FILE_UPLOADED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="file",
        resource_id=dataset_file.id,
        version_tag=dataset.current_version,
        previous_state=None,
        new_state="STORED",
        details={
            "dataset_id": dataset.id,
            "filename": dataset_file.original_filename,
            "file_size": file_size,
            "sha256_hash": sha256_hash,
        },
        ip_address=ip_address,
    )
    return dataset_file


async def upload_archive_to_dataset(
    db: AsyncSession,
    *,
    dataset: Dataset,
    zip_stream: BinaryIO,
    current_user: User,
    ip_address: Optional[str] = None,
) -> List[DatasetFile]:
    """Safely unpack an uploaded zip archive into dataset storage."""
    extracted_items = extract_safe_zip(
        dataset_id=dataset.id,
        zip_stream=zip_stream,
        uploaded_by_id=current_user.id,
        uploaded_by_username=current_user.username,
    )

    created_files: List[DatasetFile] = []
    for item in extracted_items:
        df = DatasetFile(
            dataset_id=dataset.id,
            original_filename=item["original_filename"],
            storage_name=item["storage_name"],
            storage_path=item["storage_path"],
            file_size=item["file_size"],
            mime_type=item["mime_type"],
            sha256_hash=item["sha256_hash"],
            uploaded_by_id=current_user.id,
            uploaded_by_username=current_user.username,
        )
        db.add(df)
        created_files.append(df)

    await db.flush()

    await log_event(
        db,
        action="ARCHIVE_UPLOADED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="dataset",
        resource_id=dataset.id,
        details={"files_extracted_count": len(created_files)},
        ip_address=ip_address,
    )
    return created_files


async def create_dataset_version(
    db: AsyncSession,
    *,
    dataset: Dataset,
    version_tag: Optional[str],
    current_user: User,
    ip_address: Optional[str] = None,
) -> DatasetVersion:
    """
    Freeze current files into a new cryptographically hashed version:
    1. Determine version tag (e.g. v1, v2 if not provided).
    2. Compute composite hash across all current files.
    3. Create DatasetVersion record.
    4. Link unassigned files to this version.
    5. Emit DATASET_VERSION_CREATED audit event with state change.
    """
    # Eagerly load all files
    files_res = await db.execute(
        select(DatasetFile).where(DatasetFile.dataset_id == dataset.id)
    )
    all_files = list(files_res.scalars().all())

    # Determine version label
    if not version_tag:
        versions_count_res = await db.execute(
            select(func.count(DatasetVersion.id)).where(DatasetVersion.dataset_id == dataset.id)
        )
        count = versions_count_res.scalar() or 0
        version_tag = f"v{count + 1}.0"

    total_size = sum(f.file_size for f in all_files)
    dataset_hash = compute_composite_dataset_hash(all_files)

    previous_version = dataset.current_version
    previous_hash = dataset.current_hash

    new_version = DatasetVersion(
        dataset_id=dataset.id,
        version_tag=version_tag,
        file_count=len(all_files),
        total_size=total_size,
        dataset_hash=dataset_hash,
        created_by_id=current_user.id,
        created_by_username=current_user.username,
        status=DatasetStatus.ACTIVE.value,
    )
    db.add(new_version)
    await db.flush()

    # Link files that have no version yet to this new version
    for f in all_files:
        if f.version_id is None:
            f.version_id = new_version.id

    dataset.current_version = version_tag
    dataset.current_hash = dataset_hash
    dataset.status = DatasetStatus.ACTIVE.value
    await db.flush()

    await log_event(
        db,
        action="DATASET_VERSION_CREATED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="dataset",
        resource_id=dataset.id,
        version_tag=version_tag,
        previous_state=previous_version or "UNVERSIONED",
        new_state=version_tag,
        details={
            "file_count": len(all_files),
            "total_size": total_size,
            "dataset_hash": dataset_hash,
            "previous_hash": previous_hash,
        },
        ip_address=ip_address,
    )
    return new_version


async def verify_dataset_integrity(
    db: AsyncSession,
    *,
    dataset: Dataset,
    current_user: User,
    ip_address: Optional[str] = None,
) -> DatasetVerifyResponse:
    """
    Cryptographically verify all files on disk against their recorded SHA-256 hashes:
    - Reads physical file from disk and recalculates current hash.
    - Compares expected vs disk hash.
    - If ANY mismatch is found, sets dataset.status = TAMPERED and emits DATASET_TAMPER_DETECTED.
    - If all match, sets dataset.status = VERIFIED and emits DATASET_VERIFIED.
    """
    files_res = await db.execute(
        select(DatasetFile).where(DatasetFile.dataset_id == dataset.id)
    )
    files = list(files_res.scalars().all())

    file_results: List[FileVerificationResult] = []
    tampered_count = 0
    current_files_for_hash: List[DatasetFile] = []

    for f in files:
        disk_path = UPLOAD_BASE_DIR / f.storage_path
        if not disk_path.exists():
            tampered_count += 1
            file_results.append(
                FileVerificationResult(
                    file_id=f.id,
                    filename=f.original_filename,
                    expected_hash=f.sha256_hash,
                    current_hash=None,
                    status="MISSING",
                )
            )
            continue

        disk_hash = compute_file_hash_on_disk(disk_path)
        if disk_hash != f.sha256_hash:
            tampered_count += 1
            file_results.append(
                FileVerificationResult(
                    file_id=f.id,
                    filename=f.original_filename,
                    expected_hash=f.sha256_hash,
                    current_hash=disk_hash,
                    status="TAMPERED",
                )
            )
        else:
            file_results.append(
                FileVerificationResult(
                    file_id=f.id,
                    filename=f.original_filename,
                    expected_hash=f.sha256_hash,
                    current_hash=disk_hash,
                    status="VERIFIED",
                )
            )

    is_tampered = tampered_count > 0
    previous_state = dataset.status

    if is_tampered:
        dataset.status = DatasetStatus.TAMPERED.value
        new_status = DatasetStatus.TAMPERED.value
        action = "DATASET_TAMPER_DETECTED"
        message = f"TAMPER DETECTED: {tampered_count} file(s) failed integrity verification."
    else:
        dataset.status = DatasetStatus.VERIFIED.value
        new_status = DatasetStatus.VERIFIED.value
        action = "DATASET_VERIFIED"
        message = "Integrity verified successfully. All file hashes match expected digests."

    await db.flush()

    await log_event(
        db,
        action=action,
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="dataset",
        resource_id=dataset.id,
        version_tag=dataset.current_version,
        previous_state=previous_state,
        new_state=new_status,
        details={
            "tampered_files_count": tampered_count,
            "total_files_checked": len(files),
            "expected_dataset_hash": dataset.current_hash,
        },
        ip_address=ip_address,
    )

    return DatasetVerifyResponse(
        dataset_id=dataset.id,
        status=new_status,
        expected_dataset_hash=dataset.current_hash,
        current_dataset_hash=dataset.current_hash if not is_tampered else "TAMPERED_DISCREPANCY",
        total_files_checked=len(files),
        tampered_files_count=tampered_count,
        file_results=file_results,
        message=message,
    )
