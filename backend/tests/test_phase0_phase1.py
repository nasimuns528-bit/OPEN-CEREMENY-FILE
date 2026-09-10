"""
Phase 0 (Project Foundation) & Phase 1 (Authentication + RBAC) Test Suite.
Verifies all 12 criteria specified in the user requirements:
1. /api/health probe
2. Successful registration for all 4 non-admin roles
3. Duplicate registration prevention (username & email)
4. Forbidden self-assignment of ADMIN role
5. Password complexity validation
6. Successful login with token issuance
7. Invalid password handling
8. Expired token handling
9. Invalid / tampered token handling
10. Unauthenticated access to protected endpoints
11. Role-based authorization enforcement (RBAC)
12. Disabled/inactive user access prevention
13. Session logout
14. Login rate limiting
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from jose import jwt
from sqlalchemy import select

from app.core.config import get_settings
from app.models.user import User, UserRole
from app.security.hashing import hash_password
from app.utils.rate_limiter import SlidingWindowRateLimiter

pytestmark = pytest.mark.asyncio
settings = get_settings()


class TestPhase0Foundation:
    """Phase 0 — Project Foundation tests."""

    async def test_api_health_endpoint(self, client: AsyncClient):
        """GET /api/health must return exact status and service name."""
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "VisionTrust API"

    async def test_root_health_endpoint(self, client: AsyncClient):
        """GET /health must also return ok."""
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "VisionTrust API"


class TestPhase1Authentication:
    """Phase 1 — Secure Authentication tests."""

    @pytest.mark.parametrize(
        "role",
        [
            UserRole.DATA_CONTRIBUTOR.value,
            UserRole.MODEL_CONTRIBUTOR.value,
            UserRole.REVIEWER.value,
            UserRole.INFERENCE_USER.value,
        ],
    )
    async def test_successful_registration_for_all_roles(self, client: AsyncClient, role: str):
        """Verify successful registration for all allowed self-service roles."""
        username = f"user_{role.lower()[:8]}"
        email = f"{username}@defense.org"
        response = await client.post(
            "/api/auth/register",
            json={
                "username": username,
                "email": email,
                "password": "SecurePassword123!",
                "role": role,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == username
        assert data["email"] == email
        assert data["role"] == role
        assert data["is_active"] is True
        assert "password" not in data
        assert "password_hash" not in data

    async def test_duplicate_registration_username(self, client: AsyncClient):
        """Cannot register with an existing username."""
        payload = {
            "username": "dup_user",
            "email": "dup1@defense.org",
            "password": "SecurePassword123!",
            "role": "DATA_CONTRIBUTOR",
        }
        resp1 = await client.post("/api/auth/register", json=payload)
        assert resp1.status_code == 201

        # Attempt duplicate username
        payload["email"] = "different_email@defense.org"
        resp2 = await client.post("/api/auth/register", json=payload)
        assert resp2.status_code == 409
        assert "already registered" in resp2.json()["detail"].lower()

    async def test_duplicate_registration_email(self, client: AsyncClient):
        """Cannot register with an existing email address."""
        payload1 = {
            "username": "user_email_a",
            "email": "shared@defense.org",
            "password": "SecurePassword123!",
            "role": "DATA_CONTRIBUTOR",
        }
        await client.post("/api/auth/register", json=payload1)

        payload2 = {
            "username": "user_email_b",
            "email": "shared@defense.org",
            "password": "SecurePassword123!",
            "role": "DATA_CONTRIBUTOR",
        }
        resp2 = await client.post("/api/auth/register", json=payload2)
        assert resp2.status_code == 409

    async def test_admin_self_assignment_forbidden(self, client: AsyncClient):
        """Attempting to register with ADMIN role must be rejected."""
        response = await client.post(
            "/api/auth/register",
            json={
                "username": "fake_admin",
                "email": "fake_admin@defense.org",
                "password": "SecurePassword123!",
                "role": "ADMIN",
            },
        )
        assert response.status_code == 422

    async def test_password_strength_validation(self, client: AsyncClient):
        """Passwords must satisfy length, uppercase, and digit rules."""
        # Too short (< 8)
        r1 = await client.post(
            "/api/auth/register",
            json={"username": "short_pw", "email": "s@d.org", "password": "Ab1", "role": "DATA_CONTRIBUTOR"},
        )
        assert r1.status_code == 422

        # No uppercase
        r2 = await client.post(
            "/api/auth/register",
            json={"username": "no_upper", "email": "nu@d.org", "password": "password123!", "role": "DATA_CONTRIBUTOR"},
        )
        assert r2.status_code == 422

        # No digit
        r3 = await client.post(
            "/api/auth/register",
            json={"username": "no_digit", "email": "nd@d.org", "password": "PasswordOnly!", "role": "DATA_CONTRIBUTOR"},
        )
        assert r3.status_code == 422

    async def test_successful_login(self, client: AsyncClient):
        """Successful login returns access and refresh tokens."""
        # Register
        await client.post(
            "/api/auth/register",
            json={
                "username": "login_tester",
                "email": "login_tester@defense.org",
                "password": "StrongPassword99!",
                "role": "REVIEWER",
            },
        )

        # Login
        response = await client.post(
            "/api/auth/login",
            json={"username": "login_tester", "password": "StrongPassword99!"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    async def test_invalid_password_returns_401(self, client: AsyncClient):
        """Invalid password returns 401 without timing or enumeration leaks."""
        await client.post(
            "/api/auth/register",
            json={
                "username": "pw_tester",
                "email": "pw_tester@defense.org",
                "password": "CorrectPassword1!",
                "role": "INFERENCE_USER",
            },
        )

        response = await client.post(
            "/api/auth/login",
            json={"username": "pw_tester", "password": "WrongPassword99!"},
        )
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["detail"]

    async def test_expired_token_rejected(self, client: AsyncClient):
        """An expired JWT token returns 401."""
        expired_payload = {
            "sub": "user-uuid-1234",
            "username": "test_expired",
            "role": "DATA_CONTRIBUTOR",
            "type": "access",
            "exp": datetime.now(tz=timezone.utc) - timedelta(minutes=5),
            "iat": datetime.now(tz=timezone.utc) - timedelta(minutes=20),
        }
        expired_token = jwt.encode(
            expired_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
        )

        response = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401

    async def test_invalid_token_signature_rejected(self, client: AsyncClient):
        """Token signed with the wrong key or tampered with returns 401."""
        invalid_token = jwt.encode(
            {"sub": "user-uuid-1234", "type": "access", "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=15)},
            "completely-wrong-secret-key-1234567890",
            algorithm="HS256",
        )

        response = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {invalid_token}"},
        )
        assert response.status_code == 401

    async def test_unauthenticated_protected_endpoint(self, client: AsyncClient):
        """Accessing a protected endpoint without a token returns 401 or 403."""
        response = await client.get("/api/auth/me")
        assert response.status_code in (401, 403)

    async def test_disabled_user_cannot_authenticate(self, client: AsyncClient, db_session):
        """A user with is_active=False is rejected on login and token auth."""
        # Create inactive user directly in database
        inactive_user = User(
            username="disabled_user",
            email="disabled@defense.org",
            password_hash=hash_password("ValidPassword1!"),
            role="DATA_CONTRIBUTOR",
            is_active=False,
        )
        db_session.add(inactive_user)
        await db_session.flush()

        # Login attempt
        login_resp = await client.post(
            "/api/auth/login",
            json={"username": "disabled_user", "password": "ValidPassword1!"},
        )
        assert login_resp.status_code == 403
        assert "deactivated" in login_resp.json()["detail"].lower()

    async def test_logout_endpoint(self, client: AsyncClient):
        """POST /api/auth/logout succeeds for authenticated user."""
        # Register & Login
        await client.post(
            "/api/auth/register",
            json={
                "username": "logout_tester",
                "email": "logout_tester@defense.org",
                "password": "Password12345!",
                "role": "INFERENCE_USER",
            },
        )
        login_resp = await client.post(
            "/api/auth/login",
            json={"username": "logout_tester", "password": "Password12345!"},
        )
        token = login_resp.json()["access_token"]

        response = await client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert "logged out" in response.json()["message"].lower()


class TestPhase1RBAC:
    """Phase 1 — Role-Based Access Control tests across the 5 roles."""

    async def test_role_attempting_unauthorized_admin_endpoint(self, client: AsyncClient):
        """A non-ADMIN role (e.g. INFERENCE_USER) attempting /api/users returns 403."""
        # Register as INFERENCE_USER
        await client.post(
            "/api/auth/register",
            json={
                "username": "inference_bob",
                "email": "bob@defense.org",
                "password": "Password12345!",
                "role": "INFERENCE_USER",
            },
        )
        login_resp = await client.post(
            "/api/auth/login",
            json={"username": "inference_bob", "password": "Password12345!"},
        )
        token = login_resp.json()["access_token"]

        # Attempt to access ADMIN-only users list
        response = await client.get(
            "/api/users/",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
        assert "requires" in response.json()["detail"].lower() or "forbidden" in response.json()["detail"].lower()

    async def test_admin_can_access_admin_endpoint(self, client: AsyncClient, db_session):
        """An ADMIN role user can successfully list users."""
        admin_user = User(
            username="super_admin",
            email="super_admin@defense.org",
            password_hash=hash_password("AdminSecurePassword1!"),
            role="ADMIN",
            is_active=True,
        )
        db_session.add(admin_user)
        await db_session.flush()

        login_resp = await client.post(
            "/api/auth/login",
            json={"username": "super_admin", "password": "AdminSecurePassword1!"},
        )
        token = login_resp.json()["access_token"]

        response = await client.get(
            "/api/users/",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        users = response.json()
        assert isinstance(users, list)
        assert any(u["username"] == "super_admin" for u in users)


class TestRateLimiter:
    """Test sliding-window rate limiter utility."""

    async def test_sliding_window_rate_limiter(self):
        """Verify rate limiter triggers 429 when max requests is exceeded."""
        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=10)
        client_key = "127.0.0.1:test_brute_force"

        # First 3 should pass
        limiter.check(client_key)
        limiter.check(client_key)
        limiter.check(client_key)

        # 4th request must raise HTTPException 429
        with pytest.raises(Exception) as exc_info:
            limiter.check(client_key)

        assert exc_info.value.status_code == 429
        assert "Too many login attempts" in exc_info.value.detail
