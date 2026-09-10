"""
Pydantic schemas for Dataset, DatasetVersion, and DatasetFile operations.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class DatasetCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128, description="Dataset title")
    description: Optional[str] = Field(None, max_length=2000, description="Detailed description")


class DatasetFileResponse(BaseModel):
    id: str
    dataset_id: str
    version_id: Optional[str] = None
    original_filename: str
    storage_name: str
    file_size: int
    mime_type: str
    sha256_hash: str
    uploaded_by_id: str
    uploaded_by_username: str
    created_at: datetime

    class Config:
        from_attributes = True


class DatasetVersionResponse(BaseModel):
    id: str
    dataset_id: str
    version_tag: str
    file_count: int
    total_size: int
    dataset_hash: str
    created_by_id: str
    created_by_username: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class DatasetResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    owner_id: str
    owner_username: str
    status: str
    current_version: Optional[str] = None
    current_hash: Optional[str] = None
    file_count: int = 0
    total_size: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DatasetDetailResponse(DatasetResponse):
    files: List[DatasetFileResponse] = []
    versions: List[DatasetVersionResponse] = []


class DatasetVersionCreate(BaseModel):
    version_tag: Optional[str] = Field(None, description="Optional version label, e.g. v1, v2 (auto-increments if empty)")


class FileVerificationResult(BaseModel):
    file_id: str
    filename: str
    expected_hash: str
    current_hash: Optional[str] = None
    status: str  # "VERIFIED" | "TAMPERED" | "MISSING"


class DatasetVerifyResponse(BaseModel):
    dataset_id: str
    status: str  # "VERIFIED" | "TAMPERED"
    expected_dataset_hash: Optional[str]
    current_dataset_hash: Optional[str]
    total_files_checked: int
    tampered_files_count: int
    file_results: List[FileVerificationResult]
    message: str
