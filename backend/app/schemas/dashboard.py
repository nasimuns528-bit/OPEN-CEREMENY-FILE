"""
Pydantic schemas for the Trust Dashboard and Integrity Assurance Scoring engine.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScoringComponent(BaseModel):
    key: str
    name: str
    score: float
    max_score: float
    status: str  # "OPTIMAL" | "ATTENTION" | "DEGRADED"
    explanation: str
    details: Dict[str, Any] = {}


class SecurityAlertItem(BaseModel):
    id: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"
    category: str  # "DATASET" | "MODEL" | "AUDIT" | "INFERENCE"
    title: str
    description: str
    timestamp: datetime


class TrustMetricsResponse(BaseModel):
    assurance_score: float
    label: str = "Integrity Assurance Score"
    rating: str  # "HIGH ASSURANCE" | "MODERATE ASSURANCE" | "COMPROMISED"
    disclaimer: str = (
        "Integrity assurance metrics measure system provenance, cryptographic hash consistency, "
        "and security scanning; not mathematical proof of AI correctness."
    )
    scoring_breakdown: List[ScoringComponent]

    # Pipeline Summaries
    datasets_summary: Dict[str, Any]
    models_summary: Dict[str, Any]
    inference_summary: Dict[str, Any]
    audit_chain_status: Dict[str, Any]

    # Security Alerts
    active_alerts_count: int
    security_alerts: List[SecurityAlertItem]

    generated_at: datetime

    model_config = ConfigDict(protected_namespaces=())
