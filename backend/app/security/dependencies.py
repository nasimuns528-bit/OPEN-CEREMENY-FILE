"""
Security and RBAC dependencies for FastAPI routes.
Validates Bearer tokens, ensures accounts are active, and checks role permissions.
"""
from __future__ import annotations

from typing import Sequence

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.security.tokens import decode_token

bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and validate Bearer token, retrieving the user record.
    Rejects missing/invalid/expired tokens with 401.
    Rejects inactive/disabled users with 403.
    """
    token = credentials.credentials
    payload = decode_token(token)

    if payload is None or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str = payload.get("sub", "")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated.",
        )

    return user


def require_role(*roles: str):
    """
    Returns a FastAPI dependency that enforces membership in one of the specified roles.
    Example: Depends(require_role("ADMIN"))
    """
    allowed = set(r.upper() for r in roles)

    async def _check(current_user: User = Depends(get_current_user)) -> User:
        user_role = (current_user.role or "").upper()
        if user_role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden. Requires one of: {', '.join(sorted(allowed))}.",
            )
        return current_user

    return _check


def get_client_ip(request: Request) -> str:
    """Extract client IP, taking X-Forwarded-For into account."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
