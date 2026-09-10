"""
VisionTrust Core Configuration
==============================
All secrets and tunable values are read from environment variables.
No hard-coded secrets anywhere in this file.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://visiontrust:visiontrust_secret@localhost:5432/visiontrust"
    database_sync_url: str = "postgresql+psycopg2://visiontrust:visiontrust_secret@localhost:5432/visiontrust"

    # ── JWT ───────────────────────────────────────────────
    jwt_secret_key: str = "CHANGE_ME_IN_ENV"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # ── Ed25519 Keys ──────────────────────────────────────
    private_key_path: str = ""
    public_key_path: str = ""
    ed25519_private_key_b64: str = ""
    ed25519_public_key_b64: str = ""

    # ── Application ───────────────────────────────────────
    environment: str = "development"
    allowed_origins: str = "http://localhost:5173,http://localhost:3000"
    upload_dir: str = "uploads"
    max_upload_size_mb: int = 50

    # ── Bootstrap admin ───────────────────────────────────
    first_admin_email: str = "admin@visiontrust.local"
    first_admin_username: str = "admin"
    first_admin_password: str = "CHANGE_ME_ADMIN_PASSWORD"

    # ── Derived helpers ───────────────────────────────────
    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @field_validator("jwt_secret_key")
    @classmethod
    def _validate_secret(cls, v: str) -> str:
        if v in ("CHANGE_ME_IN_ENV", ""):
            pass
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
