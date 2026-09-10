"""
Argon2id password hashing and verification.
Uses OWASP-recommended parameters: time_cost=3, memory_cost=64MB, parallelism=4.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain: str) -> str:
    """Hash a plaintext password with Argon2id. Returns the encoded hash string."""
    return _ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.
    Returns True if correct, False otherwise.
    Timing-safe; never raises on mismatch.
    """
    try:
        _ph.verify(hashed, plain)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """Check if a stored hash needs to be upgraded."""
    return _ph.check_needs_rehash(hashed)
