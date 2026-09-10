"""
Phase 5 — Computer Vision Inference Engine and Cryptographic Evidence Records Tests.
Verifies:
- Valid image decoding and CV object detection inference
- Generation of input hash, model hash, output hash, and Ed25519 evidence signature
- Blocking inference when selected model is unapproved (400 Bad Request, INFERENCE_BLOCKED audit logged)
- Blocking inference when selected model is tampered on disk (400 Bad Request)
- Rejection of invalid/corrupted images (Pillow/OpenCV decode failure)
- Trustworthy terminology compliance: 'Model prediction' & 'Integrity verified'
"""
import io
import pytest
from PIL import Image
from httpx import AsyncClient
from app.security.ed25519 import verify_evidence_record
from app.utils.storage import UPLOAD_BASE_DIR


def create_test_image_bytes(width: int = 200, height: int = 150) -> bytes:
    """Generate valid PNG image bytes for testing."""
    img = Image.new("RGB", (width, height), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
async def setup_approved_model(client: AsyncClient) -> dict:
    """Create, upload clean weights for, and approve a model version."""
    # 1. Register contributor & reviewer
    await client.post(
        "/api/auth/register",
        json={
            "username": "cv_contrib",
            "email": "cv_contrib@example.com",
            "password": "ContribPass1",
            "role": "MODEL_CONTRIBUTOR",
        },
    )
    c_tok = (
        await client.post(
            "/api/auth/login",
            json={"username": "cv_contrib", "password": "ContribPass1"},
        )
    ).json()["access_token"]

    await client.post(
        "/api/auth/register",
        json={
            "username": "cv_rev",
            "email": "cv_rev@example.com",
            "password": "ReviewerPass1",
            "role": "REVIEWER",
        },
    )
    r_tok = (
        await client.post(
            "/api/auth/login",
            json={"username": "cv_rev", "password": "ReviewerPass1"},
        )
    ).json()["access_token"]

    # 2. Create model
    m_res = await client.post(
        "/api/models",
        headers={"Authorization": f"Bearer {c_tok}"},
        json={"name": "YOLOv8 Autonomous Vehicle", "framework": "YOLOv8"},
    )
    model_id = m_res.json()["id"]

    # 3. Upload clean weights
    clean_bytes = b"PK\x03\x04torch_clean_vehicle_detection_v1"
    v_res = await client.post(
        f"/api/models/{model_id}/versions",
        headers={"Authorization": f"Bearer {c_tok}"},
        data={"version_tag": "v1.0"},
        files={"file": ("yolov8n.pt", io.BytesIO(clean_bytes), "application/octet-stream")},
    )
    version_id = v_res.json()["id"]
    storage_name = v_res.json()["storage_name"]

    # 4. Approve model version
    app_res = await client.post(
        f"/api/models/{model_id}/versions/{version_id}/approve",
        headers={"Authorization": f"Bearer {r_tok}"},
    )
    approved = app_res.json()

    return {
        "model_id": model_id,
        "version_id": version_id,
        "storage_name": storage_name,
        "model_hash": approved["sha256_hash"],
        "public_key": approved["ed25519_public_key"],
        "contrib_token": c_tok,
        "reviewer_token": r_tok,
    }


@pytest.fixture
async def inference_user_token(client: AsyncClient) -> str:
    """Register and login an INFERENCE_USER."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "driver_app",
            "email": "driver_app@example.com",
            "password": "DriverPass1",
            "role": "INFERENCE_USER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "driver_app", "password": "DriverPass1"},
    )
    return res.json()["access_token"]


@pytest.mark.asyncio
class TestComputerVisionInference:
    async def test_valid_image_inference_success(
        self, client: AsyncClient, setup_approved_model: dict, inference_user_token: str
    ):
        """
        Valid inference test:
        - Decodes image
        - Runs CV object detection
        - Computes input hash, model hash, output hash
        - Issues Ed25519 evidence signature
        - Enforces trustworthy wording
        """
        model_id = setup_approved_model["model_id"]
        version_id = setup_approved_model["version_id"]
        image_bytes = create_test_image_bytes(300, 200)

        res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {inference_user_token}"},
            data={"model_id": model_id, "version_id": version_id},
            files={"image": ("road_frame.png", io.BytesIO(image_bytes), "image/png")},
        )
        assert res.status_code == 200
        data = res.json()

        # Check prediction results
        assert len(data["predictions"]) > 0
        assert data["highest_confidence"] > 0.0
        assert len(data["input_hash"]) == 64
        assert len(data["output_hash"]) == 64
        assert data["model_hash"] == setup_approved_model["model_hash"]
        assert data["evidence_signature"] is not None

        # Verify trustworthy terminology
        assert data["verification_status"] == "Integrity verified"
        assert "Model prediction" in data["statement"]
        assert "guaranteed correct" not in data["statement"].lower()

        # Cryptographically verify the evidence signature
        is_sig_valid = verify_evidence_record(
            public_key_hex=setup_approved_model["public_key"],
            input_hash=data["input_hash"],
            model_hash=data["model_hash"],
            output_hash=data["output_hash"],
            signature_hex=data["evidence_signature"],
        )
        assert is_sig_valid is True

    async def test_inference_stored_in_records(
        self, client: AsyncClient, setup_approved_model: dict, inference_user_token: str
    ):
        """Historical inference evidence records are queryable with full provenance."""
        model_id = setup_approved_model["model_id"]
        image_bytes = create_test_image_bytes(250, 200)

        inf_res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {inference_user_token}"},
            data={"model_id": model_id},
            files={"image": ("camera_1.png", io.BytesIO(image_bytes), "image/png")},
        )
        record_id = inf_res.json()["inference_id"]

        # Fetch record by ID
        rec_res = await client.get(
            f"/api/inference/records/{record_id}",
            headers={"Authorization": f"Bearer {inference_user_token}"},
        )
        assert rec_res.status_code == 200
        rec = rec_res.json()
        assert rec["id"] == record_id
        assert rec["executor_username"] == "driver_app"
        assert rec["verification_status"] == "Integrity verified"
        assert len(rec["predictions"]) > 0

    async def test_block_inference_on_unapproved_model(
        self, client: AsyncClient, setup_approved_model: dict, inference_user_token: str
    ):
        """Inference is strictly blocked on an unapproved model version."""
        model_id = setup_approved_model["model_id"]
        c_tok = setup_approved_model["contrib_token"]

        # Upload an unapproved v2 version
        v2_res = await client.post(
            f"/api/models/{model_id}/versions",
            headers={"Authorization": f"Bearer {c_tok}"},
            data={"version_tag": "v2.0-draft"},
            files={"file": ("v2_draft.pt", io.BytesIO(b"PK\x03\x04unapproved"), "application/octet-stream")},
        )
        v2_id = v2_res.json()["id"]

        # Attempt to run inference on unapproved model
        image_bytes = create_test_image_bytes()
        res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {inference_user_token}"},
            data={"model_id": model_id, "version_id": v2_id},
            files={"image": ("test.png", io.BytesIO(image_bytes), "image/png")},
        )
        assert res.status_code == 400
        assert "not approved" in res.json()["detail"].lower()

        # Check INFERENCE_BLOCKED audit event
        audit_res = await client.get(
            "/api/audit?action=INFERENCE_BLOCKED",
            headers={"Authorization": f"Bearer {setup_approved_model['reviewer_token']}"},
        )
        assert audit_res.status_code == 200
        assert len(audit_res.json()) >= 1

    async def test_block_inference_on_tampered_model(
        self, client: AsyncClient, setup_approved_model: dict, inference_user_token: str
    ):
        """
        CONTROLLED INFERENCE TAMPER TEST:
        1. Intentionally modify approved model file on disk.
        2. Attempt inference.
        3. Confirm inference is BLOCKED with hash mismatch.
        """
        model_id = setup_approved_model["model_id"]
        version_id = setup_approved_model["version_id"]
        storage_name = setup_approved_model["storage_name"]

        # Tamper the model on disk
        disk_path = UPLOAD_BASE_DIR / "models" / model_id / storage_name
        with open(disk_path, "wb") as f:
            f.write(b"PK\x03\x04TAMPERED_INFERENCE_ATTACK_VECTOR")

        image_bytes = create_test_image_bytes()
        res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {inference_user_token}"},
            data={"model_id": model_id, "version_id": version_id},
            files={"image": ("target.png", io.BytesIO(image_bytes), "image/png")},
        )
        assert res.status_code == 400
        assert "tampered" in res.json()["detail"].lower()

    async def test_reject_corrupted_image(
        self, client: AsyncClient, setup_approved_model: dict, inference_user_token: str
    ):
        """Corrupted image bytes are rejected with 400 Bad Request."""
        model_id = setup_approved_model["model_id"]
        version_id = setup_approved_model["version_id"]

        corrupt_bytes = b"NOT_A_VALID_IMAGE_RANDOM_GARBAGE_PAYLOAD"
        res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {inference_user_token}"},
            data={"model_id": model_id, "version_id": version_id},
            files={"image": ("corrupted.png", io.BytesIO(corrupt_bytes), "image/png")},
        )
        assert res.status_code == 400
        assert "corrupted" in res.json()["detail"].lower() or "failed to decode" in res.json()["detail"].lower()
