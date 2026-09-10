"""
Pydantic v2 schemas for authentication and user management.
Enforces the 5 official VisionTrust RBAC roles and password strength requirements.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# Valid registration roles (publicly assignable)
ALLOWED_REGISTER_ROLES = (
    "DATA_CONTRIBUTOR",
    "MODEL_CONTRIBUTOR",
    "REVIEWER",
    "INFERENCE_USER",
    # Legacy aliases normalized automatically
    "contributor",
    "viewer",
)

ALL_SYSTEM_ROLES = (
    "ADMIN",
    "DATA_CONTRIBUTOR",
    "MODEL_CONTRIBUTOR",
    "REVIEWER",
    "INFERENCE_USER",
    "admin",
    "contributor",
    "viewer",
)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    role: str = "DATA_CONTRIBUTOR"

    @field_validator("password")
    @classmethod
    def _password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit.")
        return v

    @field_validator("username")
    @classmethod
    def _username_lower(cls, v: str) -> str:
        return v.lower()

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper == "ADMIN":
            raise ValueError("The ADMIN role cannot be self-assigned.")

        role_map = {
            "DATA_CONTRIBUTOR": "DATA_CONTRIBUTOR",
            "MODEL_CONTRIBUTOR": "MODEL_CONTRIBUTOR",
            "REVIEWER": "REVIEWER",
            "INFERENCE_USER": "INFERENCE_USER",
            "CONTRIBUTOR": "DATA_CONTRIBUTOR",
            "VIEWER": "INFERENCE_USER",
        }
        if v_upper not in role_map:
            raise ValueError(
                f"Invalid role. Allowed roles: DATA_CONTRIBUTOR, MODEL_CONTRIBUTOR, REVIEWER, INFERENCE_USER."
            )
        return role_map[v_upper]


class RegisterResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool = True
    created_at: datetime
    message: str = "User registered successfully"


# ── Login ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


# ── Refresh ───────────────────────────────────────────────────────────────────

class RefreshRequest(BaseModel):
    refresh_token: str


# ── Current user ─────────────────────────────────────────────────────────────

class UserProfile(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


# ── Admin user list ───────────────────────────────────────────────────────────

class UserListItem(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def _validate_update_role(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v_upper = v.upper()
        role_map = {
            "ADMIN": "ADMIN",
            "DATA_CONTRIBUTOR": "DATA_CONTRIBUTOR",
            "MODEL_CONTRIBUTOR": "MODEL_CONTRIBUTOR",
            "REVIEWER": "REVIEWER",
            "INFERENCE_USER": "INFERENCE_USER",
            "CONTRIBUTOR": "DATA_CONTRIBUTOR",
            "VIEWER": "INFERENCE_USER",
        }
        if v_upper not in role_map:
            raise ValueError(f"Invalid role. Must be one of: {', '.join(role_map.keys())}")
        return role_map[v_upper]
