"""
JWT access and refresh token generation and verification.
Validates cryptographic signature and expiration.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from app.core.config import get_settings

settings = get_settings()


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def create_access_token(user_id: str, username: str, role: str) -> str:
    """Create a short-lived signed JWT access token."""
    expire = _utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "type": "access",
        "exp": expire,
        "iat": _utcnow(),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str) -> str:
    """Create a longer-lived signed JWT refresh token."""
    expire = _utcnow() + timedelta(days=settings.refresh_token_expire_days)
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": expire,
        "iat": _utcnow(),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and cryptographically validate a JWT.
    Returns the payload dictionary or None if expired/tampered/invalid.
    """
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError:
        return None
