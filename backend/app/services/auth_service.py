"""
Authentication and authorization service.
Re-exports from app.security modules for backwards compatibility.
"""
from __future__ import annotations

from app.security.hashing import hash_password, needs_rehash, verify_password
from app.security.tokens import create_access_token, create_refresh_token, decode_token

__all__ = [
    "hash_password",
    "verify_password",
    "needs_rehash",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
]
