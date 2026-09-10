"""
Pydantic schemas for Computer Vision Inference and Evidence Records.
Enforces trustworthy terminology: 'Model prediction' and 'Integrity verified'.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class DetectionItem(BaseModel):
    class_name: str
    confidence: float
    bbox: List[int] = Field(..., description="[x1, y1, x2, y2] pixel coordinates")


class InferenceResponse(BaseModel):
    inference_id: str
    input_filename: str
    input_hash: str
    model_id: str
    model_version_tag: str
    model_hash: str
    predictions: List[DetectionItem]
    highest_confidence: float
    output_hash: str
    evidence_hash: Optional[str] = None
    evidence_signature: Optional[str] = None
    verification_status: str = Field(..., description="Integrity verified status")
    statement: str = "Model prediction — integrity verified across data, model, and execution pipeline."
    created_at: datetime

    model_config = ConfigDict(protected_namespaces=())


class InferenceRecordResponse(BaseModel):
    id: str
    input_filename: str
    input_hash: str
    model_id: str
    model_version_tag: str
    model_hash: str
    highest_confidence: float
    output_hash: str
    evidence_hash: Optional[str] = None
    evidence_signature: Optional[str] = None
    signing_algorithm: Optional[str] = "Ed25519"
    public_key: Optional[str] = None
    verification_status: str
    executor_username: str
    created_at: datetime
    predictions: List[DetectionItem] = []

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


class InferenceVerifyResponse(BaseModel):
    inference_id: str
    input_integrity: bool
    model_integrity: bool
    provenance_valid: bool
    evidence_integrity: bool
    signature_valid: bool
    overall_status: str  # "VERIFIED" | "TAMPERED" | "NOT_VERIFIED"
    discrepancies: List[str] = []
    evidence_hash: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(protected_namespaces=())
