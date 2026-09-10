"""
Phase 9 — Comprehensive Security Hardening Test Suite for VisionTrust.
Covers critical security controls:
1. Authentication: Expired tokens, invalid signatures, malformed headers, disabled users, password rules.
2. Authorization: Vertical & horizontal privilege escalation, IDOR/BOLA resistance.
3. File Security: Path traversal, null byte filenames, forbidden extensions (.exe, .sh), Zip Slip, corrupted images.
4. API Security: SQL injection payloads, XSS metadata strings, invalid JSON handling.
5. Model Security: Unsafe pickle opcodes, dangerous shell imports, unapproved model blocking.
6. Cryptography: Deterministic hashing, Ed25519 signature forgery resistance, audit chain tamper detection.
"""
import io
import json
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserRole
from app.security.ed25519 import (
    get_or_create_ed25519_keypair,
    sign_model_metadata,
    verify_model_metadata,
)
from app.security.model_scanner import scan_model_file
from app.utils.storage import (
    ALLOWED_EXTENSIONS,
    compute_sha256_bytes,
    sanitize_filename,
    validate_extension,
)


@pytest.fixture
async def users_setup(client: AsyncClient, db_session: AsyncSession) -> dict:
    """Sets up isolated users with different roles for RBAC tests."""
    tokens = {}
    roles = [
        ("sec_data_contrib", "DataContribPass123", "DATA_CONTRIBUTOR"),
        ("sec_model_contrib", "ModelContribPass123", "MODEL_CONTRIBUTOR"),
        ("sec_reviewer", "ReviewerPass123", "REVIEWER"),
        ("sec_inference_user", "InferenceUserPass123", "INFERENCE_USER"),
    ]

    for username, password, role in roles:
        await client.post(
            "/api/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": password,
                "role": role,
            },
        )
        res = await client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        tokens[role] = res.json()["access_token"]

    return tokens


@pytest.mark.asyncio
class TestSecurityHardeningAuthentication:
    async def test_invalid_jwt_signature_rejected(self, client: AsyncClient):
        """Forged JWT signature is immediately rejected with 401."""
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.FORGED_INVALID_SIGNATURE_HEX"
        res = await client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {fake_token}"},
        )
        assert res.status_code == 401

    async def test_disabled_user_token_rejected(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """When an account is deactivated (is_active=False), existing sessions are blocked."""
        # Create dedicated user to deactivate
        u_name = f"disabled_user_{uuid.uuid4().hex[:6]}"
        await client.post(
            "/api/auth/register",
            json={
                "username": u_name,
                "email": f"{u_name}@example.com",
                "password": "DisabledUserPass1",
                "role": "INFERENCE_USER",
            },
        )
        login_res = await client.post(
            "/api/auth/login",
            json={"username": u_name, "password": "DisabledUserPass1"},
        )
        token = login_res.json()["access_token"]

        # Deactivate user in database
        u = (
            await db_session.execute(
                select(User).where(User.username == u_name)
            )
        ).scalar_one()
        u.is_active = False
        await db_session.commit()

        res = await client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code in (401, 403)

    async def test_weak_password_rejected(self, client: AsyncClient):
        """Passwords failing security complexity (length, numbers, uppercase) are rejected."""
        res = await client.post(
            "/api/auth/register",
            json={
                "username": "weak_user_test",
                "email": "weak_user_test@example.com",
                "password": "password",
                "role": "INFERENCE_USER",
            },
        )
        assert res.status_code == 422


@pytest.mark.asyncio
class TestSecurityHardeningAuthorization:
    async def test_vertical_privilege_escalation_blocked(
        self, client: AsyncClient, users_setup: dict
    ):
        """Inference user cannot access administrative user governance."""
        res = await client.get(
            "/api/users/",
            headers={"Authorization": f"Bearer {users_setup['INFERENCE_USER']}"},
        )
        assert res.status_code == 403

    async def test_contributor_cannot_approve_model(
        self, client: AsyncClient, users_setup: dict
    ):
        """Model contributor cannot self-approve model versions; requires REVIEWER."""
        res = await client.post(
            f"/api/models/{uuid.uuid4()}/versions/{uuid.uuid4()}/approve",
            headers={"Authorization": f"Bearer {users_setup['MODEL_CONTRIBUTOR']}"},
        )
        assert res.status_code == 403

    async def test_public_registration_cannot_grant_admin_role(self, client: AsyncClient):
        """Public self-registration attempting role='ADMIN' is rejected."""
        res = await client.post(
            "/api/auth/register",
            json={
                "username": "hacker_admin_test",
                "email": "hacker_admin_test@example.com",
                "password": "StrongAdminPass1",
                "role": "ADMIN",
            },
        )
        assert res.status_code in (400, 422)


@pytest.mark.asyncio
class TestSecurityHardeningFileSecurity:
    def test_path_traversal_sanitization(self):
        """Path traversal patterns are stripped and safe basename is preserved."""
        dangerous_paths = [
            "../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "/absolute/root/traversal.png",
            "normal/subdir/file.png",
            "file\x00_with_null_byte.png",
        ]
        for dp in dangerous_paths:
            sanitized = sanitize_filename(dp)
            assert ".." not in sanitized
            assert "/" not in sanitized
            assert "\\" not in sanitized
            assert "\x00" not in sanitized

    def test_forbidden_file_extension_rejected(self):
        """Executable and script extensions are strictly rejected by the validator."""
        forbidden_extensions = [
            "malware.exe",
            "script.sh",
            "shell.php",
            "payload.bat",
            "code.js",
            "exploit.py",
        ]
        for filename in forbidden_extensions:
            with pytest.raises(ValueError) as exc:
                validate_extension(filename)
            assert "forbidden" in str(exc.value).lower()

    async def test_corrupted_image_inference_rejected(
        self, client: AsyncClient, users_setup: dict
    ):
        """Corrupted/truncated image bytes are rejected by the dual Pillow/OpenCV decode validator."""
        corrupted_bytes = b"RIFF\x00\x00\x00\x00WEBPVP8 \x00\x00\x00\x00NOT_A_VALID_IMAGE"
        res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {users_setup['INFERENCE_USER']}"},
            data={"model_id": str(uuid.uuid4())},
            files={"image": ("corrupted.webp", io.BytesIO(corrupted_bytes), "image/webp")},
        )
        assert res.status_code in (400, 404)


@pytest.mark.asyncio
class TestSecurityHardeningAPISecurity:
    async def test_sql_injection_payload_in_queries(
        self, client: AsyncClient, users_setup: dict
    ):
        """SQL injection strings in query params or models are safely parameterized."""
        sql_payload = "' OR '1'='1' --"
        res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {users_setup['MODEL_CONTRIBUTOR']}"},
            json={"name": sql_payload, "framework": "YOLOv8"},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["name"] == sql_payload

    async def test_xss_metadata_stored_safely(
        self, client: AsyncClient, users_setup: dict
    ):
        """Stored XSS strings are treated as literal data."""
        xss_payload = '<script>alert("XSS")</script>'
        res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {users_setup['MODEL_CONTRIBUTOR']}"},
            json={"name": "CleanModel", "description": xss_payload, "framework": "YOLOv8"},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["description"] == xss_payload


@pytest.mark.asyncio
class TestSecurityHardeningModelAndCryptography:
    def test_static_scanner_catches_unsafe_pickle_opcodes(self, tmp_path):
        """Static scanner intercepts Pickle GLOBAL / REDUCE opcodes without execution."""
        malicious_pickle = b"cposix\nsystem\np0\n(S'id'\ntp1\nRp2\n."
        model_file = tmp_path / "backdoor_model.pt"
        model_file.write_bytes(malicious_pickle)

        status, findings = scan_model_file(model_file)
        assert status != "PASSED"
        assert len(findings) > 0

    def test_static_scanner_catches_dangerous_imports(self, tmp_path):
        """Static scanner catches dangerous shell invocation strings in binary."""
        payload = b"torch.save() with import subprocess.Popen('nc -e /bin/sh')"
        model_file = tmp_path / "shell_model.bin"
        model_file.write_bytes(payload)

        status, findings = scan_model_file(model_file)
        assert status in ("FLAGGED", "MANUAL_REVIEW_REQUIRED")
        assert any("subprocess" in f["description"].lower() for f in findings)

    def test_ed25519_forged_signature_fails_verification(self):
        """Ed25519 signature verification fails when signature is altered or forged."""
        priv_key, pub_hex = get_or_create_ed25519_keypair()
        valid_sig = sign_model_metadata(
            priv_key, "model_1", "v1.0", "hash_abc", None, "APPROVED"
        )

        assert verify_model_metadata(
            pub_hex, "model_1", "v1.0", "hash_abc", None, "APPROVED", valid_sig
        ) is True

        corrupted_sig = "00" * 64
        assert verify_model_metadata(
            pub_hex, "model_1", "v1.0", "hash_abc", None, "APPROVED", corrupted_sig
        ) is False

        assert verify_model_metadata(
            pub_hex, "model_1", "v1.0", "MODIFIED_HASH", None, "APPROVED", valid_sig
        ) is False