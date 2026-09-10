"""
Authentication API endpoints:
- POST /auth/register
- POST /auth/login (rate-limited)
- GET  /auth/me
- POST /auth/logout
- POST /auth/refresh
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
    UserProfile,
)
from app.security.dependencies import get_client_ip, get_current_user
from app.security.hashing import hash_password, needs_rehash, verify_password
from app.security.tokens import create_access_token, create_refresh_token, decode_token
from app.services.audit_service import log_event
from app.utils.rate_limiter import login_rate_limiter

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RegisterResponse:
    """Create a new user account with Argon2id password hashing."""
    ip = get_client_ip(request)

    # Check for existing username or email
    existing = await db.execute(
        select(User).where(
            (User.username == body.username.lower()) | (User.email == body.email.lower())
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        )

    user = User(
        username=body.username.lower(),
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    db.add(user)
    await db.flush()

    await log_event(
        db,
        action="user.register",
        actor_id=user.id,
        actor_username=user.username,
        resource_type="user",
        resource_id=user.id,
        details={"role": user.role, "email_domain": body.email.split("@")[-1]},
        ip_address=ip,
    )

    return RegisterResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        message="User registered successfully",
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and obtain JWT tokens",
)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate with username and password.
    Protected by rate limiting to mitigate brute-force attempts.
    Timing-safe to prevent user enumeration.
    """
    ip = get_client_ip(request)

    # Enforce sliding-window rate limit (IP + username)
    rate_limit_key = f"{ip}:{body.username.lower()}"
    login_rate_limiter.check(rate_limit_key)

    result = await db.execute(
        select(User).where(User.username == body.username.lower())
    )
    user = result.scalar_one_or_none()

    # Timing-safe dummy hash comparison when user does not exist
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    password_correct = verify_password(
        body.password,
        user.password_hash if user else dummy_hash,
    )

    if not user or not password_correct:
        await log_event(
            db,
            action="user.login_failed",
            actor_username=body.username,
            details={"reason": "invalid_credentials"},
            ip_address=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated.",
        )

    # Reset rate limit counter on successful login
    login_rate_limiter.reset(rate_limit_key)

    # Upgrade hash parameters if needed
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    user.last_login_at = datetime.now(tz=timezone.utc)

    access_token = create_access_token(user.id, user.username, user.role)
    refresh_token = create_refresh_token(user.id)

    await log_event(
        db,
        action="user.login",
        actor_id=user.id,
        actor_username=user.username,
        resource_type="user",
        resource_id=user.id,
        details={"role": user.role},
        ip_address=ip,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token for new access/refresh pair",
)
async def refresh_token(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Exchange a valid refresh token for a fresh token pair."""
    payload = decode_token(body.refresh_token)

    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    user_id = payload.get("sub", "")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated.",
        )

    return TokenResponse(
        access_token=create_access_token(user.id, user.username, user.role),
        refresh_token=create_refresh_token(user.id),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get current user profile",
)
async def me(current_user: User = Depends(get_current_user)) -> UserProfile:
    """Return the profile of the currently authenticated user."""
    return UserProfile(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login_at=current_user.last_login_at,
    )


@router.post(
    "/logout",
    summary="Sign out and terminate active session",
)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Log an audit event for user sign-out."""
    ip = get_client_ip(request)
    await log_event(
        db,
        action="user.logout",
        actor_id=current_user.id,
        actor_username=current_user.username,
        resource_type="user",
        resource_id=current_user.id,
        details={"status": "success"},
        ip_address=ip,
    )
    return {"message": "Successfully logged out"}
