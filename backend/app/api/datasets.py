"""
Datasets API router for Phase 2 (Dataset Integrity) and Phase 3 (Provenance).
Provides endpoints for dataset creation, secure file uploads, versioning,
and disk-level cryptographic verification.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.schemas.dataset import (
    DatasetCreate,
    DatasetDetailResponse,
    DatasetFileResponse,
    DatasetResponse,
    DatasetVerifyResponse,
    DatasetVersionCreate,
    DatasetVersionResponse,
)
from app.security.dependencies import get_client_ip, get_current_user, require_role
from app.services import dataset_service

router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.post(
    "",
    response_model=DatasetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new dataset (Contributor / Admin)",
)
async def create_dataset(
    payload: DatasetCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("DATA_CONTRIBUTOR", "ADMIN")),
):
    ip_addr = get_client_ip(request)
    dataset = await dataset_service.create_dataset(
        db,
        name=payload.name,
        description=payload.description,
        current_user=current_user,
        ip_address=ip_addr,
    )
    await db.commit()
    await db.refresh(dataset)
    return DatasetResponse(
        id=dataset.id,
        name=dataset.name,
        description=dataset.description,
        owner_id=dataset.owner_id,
        owner_username=dataset.owner_username,
        status=dataset.status,
        current_version=dataset.current_version,
        current_hash=dataset.current_hash,
        file_count=0,
        total_size=0,
        created_at=dataset.created_at,
        updated_at=dataset.updated_at,
    )


@router.get(
    "",
    response_model=List[DatasetResponse],
    summary="List all datasets",
)
async def list_datasets(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    datasets = await dataset_service.list_datasets(db, skip=skip, limit=limit)
    response: List[DatasetResponse] = []
    for d in datasets:
        files = d.files or []
        response.append(
            DatasetResponse(
                id=d.id,
                name=d.name,
                description=d.description,
                owner_id=d.owner_id,
                owner_username=d.owner_username,
                status=d.status,
                current_version=d.current_version,
                current_hash=d.current_hash,
                file_count=len(files),
                total_size=sum(f.file_size for f in files),
                created_at=d.created_at,
                updated_at=d.updated_at,
            )
        )
    return response


@router.get(
    "/{dataset_id}",
    response_model=DatasetDetailResponse,
    summary="Get dataset details with files and versions",
)
async def get_dataset_detail(
    dataset_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    dataset = await dataset_service.get_dataset(db, dataset_id, include_files=True)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{dataset_id}' not found.",
        )

    files = dataset.files or []
    versions = dataset.versions or []

    return DatasetDetailResponse(
        id=dataset.id,
        name=dataset.name,
        description=dataset.description,
        owner_id=dataset.owner_id,
        owner_username=dataset.owner_username,
        status=dataset.status,
        current_version=dataset.current_version,
        current_hash=dataset.current_hash,
        file_count=len(files),
        total_size=sum(f.file_size for f in files),
        created_at=dataset.created_at,
        updated_at=dataset.updated_at,
        files=[DatasetFileResponse.from_orm(f) for f in files],
        versions=[DatasetVersionResponse.from_orm(v) for v in versions],
    )


@router.post(
    "/{dataset_id}/files",
    response_model=List[DatasetFileResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Upload files or ZIP archive to dataset (Contributor / Admin)",
)
async def upload_dataset_files(
    dataset_id: str,
    request: Request,
    files: List[UploadFile] = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("DATA_CONTRIBUTOR", "ADMIN")),
):
    dataset = await dataset_service.get_dataset(db, dataset_id, include_files=False)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{dataset_id}' not found.",
        )

    ip_addr = get_client_ip(request)
    created_files: List[DatasetFileResponse] = []

    for upload_file in files:
        filename = upload_file.filename or "uploaded_file"
        # Determine if it's a zip archive
        if filename.lower().endswith(".zip"):
            try:
                extracted = await dataset_service.upload_archive_to_dataset(
                    db,
                    dataset=dataset,
                    zip_stream=upload_file.file,
                    current_user=current_user,
                    ip_address=ip_addr,
                )
                created_files.extend([DatasetFileResponse.from_orm(f) for f in extracted])
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(e),
                )
        else:
            try:
                saved = await dataset_service.upload_file_to_dataset(
                    db,
                    dataset=dataset,
                    original_filename=filename,
                    stream=upload_file.file,
                    current_user=current_user,
                    mime_type=upload_file.content_type or "application/octet-stream",
                    ip_address=ip_addr,
                )
                created_files.append(DatasetFileResponse.from_orm(saved))
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(e),
                )

    await db.commit()
    return created_files


@router.get(
    "/{dataset_id}/versions",
    response_model=List[DatasetVersionResponse],
    summary="List dataset versions",
)
async def list_dataset_versions(
    dataset_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    dataset = await dataset_service.get_dataset(db, dataset_id, include_files=True)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{dataset_id}' not found.",
        )
    return [DatasetVersionResponse.from_orm(v) for v in dataset.versions or []]


@router.post(
    "/{dataset_id}/versions",
    response_model=DatasetVersionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Freeze and create new version of dataset (Contributor / Admin)",
)
async def create_dataset_version(
    dataset_id: str,
    payload: DatasetVersionCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("DATA_CONTRIBUTOR", "ADMIN")),
):
    dataset = await dataset_service.get_dataset(db, dataset_id, include_files=True)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{dataset_id}' not found.",
        )

    ip_addr = get_client_ip(request)
    new_version = await dataset_service.create_dataset_version(
        db,
        dataset=dataset,
        version_tag=payload.version_tag,
        current_user=current_user,
        ip_address=ip_addr,
    )
    await db.commit()
    await db.refresh(new_version)
    return DatasetVersionResponse.from_orm(new_version)


@router.post(
    "/{dataset_id}/verify",
    response_model=DatasetVerifyResponse,
    summary="Cryptographically verify dataset files on disk (Reviewer / Contributor / Admin)",
)
async def verify_dataset(
    dataset_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("REVIEWER", "DATA_CONTRIBUTOR", "ADMIN")),
):
    dataset = await dataset_service.get_dataset(db, dataset_id, include_files=True)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{dataset_id}' not found.",
        )

    ip_addr = get_client_ip(request)
    verification = await dataset_service.verify_dataset_integrity(
        db,
        dataset=dataset,
        current_user=current_user,
        ip_address=ip_addr,
    )
    await db.commit()
    return verification
