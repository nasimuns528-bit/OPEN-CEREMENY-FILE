"""
User management API router (Admin operations and profile inspection).
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.schemas.auth import UserListItem, UserProfile, UserUpdateRequest
from app.security.dependencies import get_client_ip, get_current_user, require_role
from app.services.audit_service import log_event

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/",
    response_model=List[UserListItem],
    summary="List all users (Admin only)",
)
async def list_users(
    _admin: User = Depends(require_role("ADMIN")),
    db: AsyncSession = Depends(get_db),
) -> List[UserListItem]:
    """Retrieve all user accounts in the system."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return [
        UserListItem(
            id=u.id,
            username=u.username,
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at,
        )
        for u in users
    ]


@router.get(
    "/{user_id}",
    response_model=UserProfile,
    summary="Get user by ID (Self or Admin)",
)
async def get_user_by_id(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserProfile:
    """Retrieve specific user profile."""
    if current_user.id != user_id and current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own profile.",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    return UserProfile(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.patch(
    "/{user_id}",
    response_model=UserProfile,
    summary="Update user role or active status (Admin only)",
)
async def update_user(
    user_id: str,
    body: UserUpdateRequest,
    request: Request,
    admin_user: User = Depends(require_role("ADMIN")),
    db: AsyncSession = Depends(get_db),
) -> UserProfile:
    """Admin updates role or status of another user."""
    ip = get_client_ip(request)

    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    # Prevent accidental self-demotion or self-deactivation
    if target.id == admin_user.id:
        if body.role is not None and body.role.upper() != "ADMIN":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot demote themselves.",
            )
        if body.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot deactivate themselves.",
            )

    changes = {}
    if body.role is not None:
        target.role = body.role
        changes["role"] = body.role
    if body.is_active is not None:
        target.is_active = body.is_active
        changes["is_active"] = body.is_active

    await log_event(
        db,
        action="user.update",
        actor_id=admin_user.id,
        actor_username=admin_user.username,
        resource_type="user",
        resource_id=target.id,
        details=changes,
        ip_address=ip,
    )

    return UserProfile(
        id=target.id,
        username=target.username,
        email=target.email,
        role=target.role,
        is_active=target.is_active,
        created_at=target.created_at,
        last_login_at=target.last_login_at,
    )
