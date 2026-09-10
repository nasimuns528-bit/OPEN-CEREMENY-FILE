"""
Pydantic schemas for Model Catalog, Model Versions, Security Scans, and Approvals.
Protected namespaces disabled to allow model_* field names cleanly.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ModelCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = Field(None, max_length=2000)
    framework: str = Field("YOLOv8", max_length=64)
    model_type: str = Field("object_detection", max_length=64)

    model_config = ConfigDict(protected_namespaces=())


class ModelSecurityScanResponse(BaseModel):
    id: str
    model_version_id: str
    scanner_name: str
    scan_result: str
    findings_json: Optional[str] = None
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


class ModelVersionResponse(BaseModel):
    id: str
    model_id: str
    version_tag: str
    model_format: str
    file_size: int
    sha256_hash: str
    storage_name: str
    contributor_id: str
    contributor_username: str
    associated_dataset_version: Optional[str] = None
    security_scan_status: str
    approval_status: str
    approved_by_username: Optional[str] = None
    approved_at: Optional[datetime] = None
    ed25519_signature: Optional[str] = None
    ed25519_public_key: Optional[str] = None
    created_at: datetime
    scans: List[ModelSecurityScanResponse] = []

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


class ModelResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    framework: str
    model_type: str
    owner_id: str
    owner_username: str
    status: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    latest_version: Optional[str] = None
    latest_hash: Optional[str] = None
    latest_approval: Optional[str] = None

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


class ModelDetailResponse(ModelResponse):
    versions: List[ModelVersionResponse] = []


class ModelVerifyResponse(BaseModel):
    model_id: str
    version_tag: str
    file_hash_match: bool
    expected_hash: str
    current_hash: str
    scan_status: str
    approval_status: str
    signature_valid: bool
    deployment_eligible: bool
    message: str

    model_config = ConfigDict(protected_namespaces=())
