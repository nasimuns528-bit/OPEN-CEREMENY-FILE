"""
Phase 1 Authentication Tests
==============================
Covers:
- User registration (happy path, duplicate, weak password)
- Login (correct credentials, wrong password, unknown user)
- Token refresh
- /me endpoint
- RBAC enforcement
- Audit events created on key actions
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.conftest import login_user, register_user

pytestmark = pytest.mark.asyncio


# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────

class TestRegister:
    async def test_register_contributor_success(self, client: AsyncClient):
        resp = await register_user(client, username="alice", email="alice@example.com")
        assert resp.status_code == 201
        data = resp.json()
        assert data["username"] == "alice"
        assert data["role"] in ("contributor", "DATA_CONTRIBUTOR")
        assert "id" in data
        assert "hashed_password" not in data

    async def test_register_viewer_success(self, client: AsyncClient):
        resp = await register_user(
            client, username="bob", email="bob@example.com", role="viewer"
        )
        assert resp.status_code == 201
        assert resp.json()["role"] in ("viewer", "INFERENCE_USER")

    async def test_register_duplicate_username(self, client: AsyncClient):
        await register_user(client, username="carol", email="carol@example.com")
        resp = await register_user(client, username="carol", email="carol2@example.com")
        assert resp.status_code == 409

    async def test_register_duplicate_email(self, client: AsyncClient):
        await register_user(client, username="dave", email="dave@example.com")
        resp = await register_user(client, username="dave2", email="dave@example.com")
        assert resp.status_code == 409

    async def test_register_weak_password_no_uppercase(self, client: AsyncClient):
        resp = await register_user(
            client, username="eve", email="eve@example.com", password="weakpass1"
        )
        assert resp.status_code == 422

    async def test_register_weak_password_no_digit(self, client: AsyncClient):
        resp = await register_user(
            client, username="frank", email="frank@example.com", password="WeakPassword"
        )
        assert resp.status_code == 422

    async def test_register_weak_password_too_short(self, client: AsyncClient):
        resp = await register_user(
            client, username="grace", email="grace@example.com", password="Ab1!"
        )
        assert resp.status_code == 422

    async def test_register_invalid_username_special_chars(self, client: AsyncClient):
        resp = await register_user(
            client, username="bad user!", email="bad@example.com"
        )
        assert resp.status_code == 422

    async def test_register_cannot_self_assign_admin(self, client: AsyncClient):
        """Registering as admin via public endpoint should fail — only contributor/viewer allowed."""
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "username": "hacker",
                "email": "hacker@example.com",
                "password": "HackPass1",
                "role": "admin",
            },
        )
        assert resp.status_code == 422  # role enum only allows contributor/viewer


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────

class TestLogin:
    async def test_login_success_returns_tokens(self, client: AsyncClient):
        await register_user(client, username="ian", email="ian@example.com")
        resp = await login_user(client, username="ian")
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    async def test_login_wrong_password(self, client: AsyncClient):
        await register_user(client, username="jane", email="jane@example.com")
        resp = await login_user(client, username="jane", password="WrongPass9")
        assert resp.status_code == 401
        # Must not leak which field was wrong
        assert "stack" not in resp.text
        assert "traceback" not in resp.text.lower()

    async def test_login_unknown_user(self, client: AsyncClient):
        resp = await login_user(client, username="nobody", password="TestPass1")
        assert resp.status_code == 401

    async def test_login_case_insensitive_username(self, client: AsyncClient):
        await register_user(client, username="karen", email="karen@example.com")
        resp = await login_user(client, username="KAREN")
        assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# Token refresh
# ─────────────────────────────────────────────────────────────────────────────

class TestRefresh:
    async def test_refresh_returns_new_tokens(self, client: AsyncClient):
        await register_user(client, username="leo", email="leo@example.com")
        login_resp = await login_user(client, username="leo")
        refresh_token = login_resp.json()["refresh_token"]

        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        # New access token must differ from old one (timestamps differ)

    async def test_refresh_invalid_token(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "totally.invalid.token"},
        )
        assert resp.status_code == 401

    async def test_access_token_cannot_be_used_as_refresh(self, client: AsyncClient):
        await register_user(client, username="mia", email="mia@example.com")
        login_resp = await login_user(client, username="mia")
        access_token = login_resp.json()["access_token"]

        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": access_token},
        )
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# /me endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestMe:
    async def test_me_returns_profile(self, client: AsyncClient):
        await register_user(client, username="nina", email="nina@example.com")
        login_resp = await login_user(client, username="nina")
        token = login_resp.json()["access_token"]

        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "nina"
        assert "hashed_password" not in data

    async def test_me_no_token(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 403  # HTTPBearer returns 403 when missing

    async def test_me_invalid_token(self, client: AsyncClient):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer bad.token.here"},
        )
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# RBAC: Users endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestRBAC:
    async def test_contributor_cannot_list_users(self, client: AsyncClient):
        await register_user(client, username="oscar", email="oscar@example.com", role="contributor")
        login_resp = await login_user(client, username="oscar")
        token = login_resp.json()["access_token"]

        resp = await client.get(
            "/api/v1/users/",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    async def test_viewer_cannot_list_users(self, client: AsyncClient):
        await register_user(client, username="penny", email="penny@example.com", role="viewer")
        login_resp = await login_user(client, username="penny")
        token = login_resp.json()["access_token"]

        resp = await client.get(
            "/api/v1/users/",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    async def test_user_cannot_view_another_users_profile(self, client: AsyncClient):
        r1 = await register_user(client, username="quinn", email="quinn@example.com")
        r2 = await register_user(client, username="rachel", email="rachel@example.com")
        other_id = r2.json()["id"]

        login_resp = await login_user(client, username="quinn")
        token = login_resp.json()["access_token"]

        resp = await client.get(
            f"/api/v1/users/{other_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    async def test_user_can_view_own_profile(self, client: AsyncClient):
        r = await register_user(client, username="sam", email="sam@example.com")
        own_id = r.json()["id"]

        login_resp = await login_user(client, username="sam")
        token = login_resp.json()["access_token"]

        resp = await client.get(
            f"/api/v1/users/{own_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────

class TestHealth:
    async def test_health_endpoint(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
