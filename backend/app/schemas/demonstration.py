"""
Pydantic schemas for Phase 8 Controlled Integrity Attack Demonstration.
Captures step-by-step telemetry, cryptographic digests, and display banners.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AttackStepResult(BaseModel):
    step_number: int
    action: str
    status: str  # "SUCCESS" | "TAMPER_DETECTED" | "BLOCKED" | "INFO"
    details: str
    metadata: Dict[str, Any] = {}


class AttackDemonstrationResponse(BaseModel):
    scenario_id: str
    scenario_name: str
    display_title: str
    tamper_detected: bool
    inference_status: Optional[str] = None
    telemetry: Dict[str, Any] = {}
    steps: List[AttackStepResult] = []
    timestamp: datetime

    model_config = ConfigDict(protected_namespaces=())