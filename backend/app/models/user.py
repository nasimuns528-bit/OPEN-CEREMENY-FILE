"""
SQLAlchemy ORM model for application users.
Enforces the 5 official VisionTrust RBAC roles:
- ADMIN
- DATA_CONTRIBUTOR
- MODEL_CONTRIBUTOR
- REVIEWER
- INFERENCE_USER
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    DATA_CONTRIBUTOR = "DATA_CONTRIBUTOR"
    MODEL_CONTRIBUTOR = "MODEL_CONTRIBUTOR"
    REVIEWER = "REVIEWER"
    INFERENCE_USER = "INFERENCE_USER"

    # Compatibility aliases
    contributor = "DATA_CONTRIBUTOR"
    viewer = "INFERENCE_USER"
    admin = "ADMIN"

    @classmethod
    def valid_registration_roles(cls) -> list[str]:
        """Roles allowed for public self-registration (excluding ADMIN)."""
        return [
            cls.DATA_CONTRIBUTOR.value,
            cls.MODEL_CONTRIBUTOR.value,
            cls.REVIEWER.value,
            cls.INFERENCE_USER.value,
        ]


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=UserRole.DATA_CONTRIBUTOR.value,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=func.now(),
        onupdate=func.now(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Backwards compatibility property
    @property
    def hashed_password(self) -> str:
        return self.password_hash

    @hashed_password.setter
    def hashed_password(self, value: str) -> None:
        self.password_hash = value

    def __repr__(self) -> str:
        return f"<User id={self.id!r} username={self.username!r} role={self.role!r}>"
