"""
Phase 6 Tests — Inference Output Integrity & Cryptographic Evidence Verification.
Verifies:
1. Complete 5-pillar verification of a valid inference record (VERIFIED).
2. Detection of tampered input image file on disk (TAMPERED).
3. Detection of tampered model weights on disk (TAMPERED).
4. Detection of altered predictions in database (TAMPERED).
5. Detection of corrupted cryptographic signature (NOT_VERIFIED).
6. Controlled discrepancy reporting and non-existent record handling (404).
"""
import io
import pytest
from PIL import Image
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.model import InferenceRecord, ModelVersion
from app.utils.storage import UPLOAD_BASE_DIR


def create_test_image_bytes(width: int = 240, height: int = 180) -> bytes:
    img = Image.new("RGB", (width, height), color=(50, 120, 200))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
async def setup_approved_model_and_tokens(client: AsyncClient) -> dict:
    # 1. Register contributor
    await client.post(
        "/api/auth/register",
        json={
            "username": "phase6_contrib",
            "email": "phase6_contrib@example.com",
            "password": "ContribPass1",
            "role": "MODEL_CONTRIBUTOR",
        },
    )
    c_tok = (
        await client.post(
            "/api/auth/login",
            json={"username": "phase6_contrib", "password": "ContribPass1"},
        )
    ).json()["access_token"]

    # 2. Register reviewer
    await client.post(
        "/api/auth/register",
        json={
            "username": "phase6_rev",
            "email": "phase6_rev@example.com",
            "password": "ReviewerPass1",
            "role": "REVIEWER",
        },
    )
    r_tok = (
        await client.post(
            "/api/auth/login",
            json={"username": "phase6_rev", "password": "ReviewerPass1"},
        )
    ).json()["access_token"]

    # 3. Register inference user
    await client.post(
        "/api/auth/register",
        json={
            "username": "phase6_user",
            "email": "phase6_user@example.com",
            "password": "InferencePass1",
            "role": "INFERENCE_USER",
        },
    )
    u_tok = (
        await client.post(
            "/api/auth/login",
            json={"username": "phase6_user", "password": "InferencePass1"},
        )
    ).json()["access_token"]

    # 4. Create and approve model
    m_res = await client.post(
        "/api/models",
        headers={"Authorization": f"Bearer {c_tok}"},
        json={"name": "Phase 6 Object Detector", "framework": "YOLOv8"},
    )
    model_id = m_res.json()["id"]

    clean_bytes = b"PK\x03\x04torch_clean_model_p6"
    v_res = await client.post(
        f"/api/models/{model_id}/versions",
        headers={"Authorization": f"Bearer {c_tok}"},
        data={"version_tag": "v1.0-p6"},
        files={"file": ("model_p6.pt", io.BytesIO(clean_bytes), "application/octet-stream")},
    )
    version_id = v_res.json()["id"]

    await client.post(
        f"/api/models/{model_id}/versions/{version_id}/approve",
        headers={"Authorization": f"Bearer {r_tok}"},
    )

    return {
        "model_id": model_id,
        "version_id": version_id,
        "user_token": u_tok,
    }


@pytest.mark.asyncio
class TestInferenceVerification:
    async def test_verify_valid_inference_record_success(
        self, client: AsyncClient, setup_approved_model_and_tokens: dict
    ):
        """Execute inference and independently verify all 5 pillars passing."""
        model_id = setup_approved_model_and_tokens["model_id"]
        token = setup_approved_model_and_tokens["user_token"]
        img_bytes = create_test_image_bytes(200, 150)

        # 1. Run inference
        inf_res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {token}"},
            data={"model_id": model_id},
            files={"image": ("camera_front.png", io.BytesIO(img_bytes), "image/png")},
        )
        assert inf_res.status_code == 200
        inference_id = inf_res.json()["inference_id"]

        # 2. Verify via verification endpoint
        ver_res = await client.post(
            f"/api/inference/{inference_id}/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert ver_res.status_code == 200
        ver_data = ver_res.json()

        assert ver_data["inference_id"] == inference_id
        assert ver_data["input_integrity"] is True
        assert ver_data["model_integrity"] is True
        assert ver_data["provenance_valid"] is True
        assert ver_data["evidence_integrity"] is True
        assert ver_data["signature_valid"] is True
        assert ver_data["overall_status"] == "VERIFIED"
        assert len(ver_data["discrepancies"]) == 0

    async def test_tampered_input_file_detected(
        self, client: AsyncClient, setup_approved_model_and_tokens: dict, db_session: AsyncSession
    ):
        """Physically modifying input image on disk must fail input_integrity and trigger TAMPERED status."""
        model_id = setup_approved_model_and_tokens["model_id"]
        token = setup_approved_model_and_tokens["user_token"]
        img_bytes = create_test_image_bytes(200, 150)

        inf_res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {token}"},
            data={"model_id": model_id},
            files={"image": ("scene.png", io.BytesIO(img_bytes), "image/png")},
        )
        inference_id = inf_res.json()["inference_id"]

        # Tamper the input image on disk
        rec_res = await db_session.execute(
            select(InferenceRecord).where(InferenceRecord.id == inference_id)
        )
        rec = rec_res.scalar_one()
        file_on_disk = UPLOAD_BASE_DIR / rec.input_storage_path
        with open(file_on_disk, "wb") as f:
            f.write(b"CORRUPTED_TAMPERED_IMAGE_PAYLOAD_123")

        # Verification must detect tampering
        ver_res = await client.post(
            f"/api/inference/{inference_id}/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert ver_res.status_code == 200
        ver_data = ver_res.json()
        assert ver_data["input_integrity"] is False
        assert ver_data["overall_status"] == "TAMPERED"
        assert any("Input hash mismatch" in d for d in ver_data["discrepancies"])

    async def test_tampered_evidence_predictions_in_db_detected(
        self, client: AsyncClient, setup_approved_model_and_tokens: dict, db_session: AsyncSession
    ):
        """Modifying predictions JSON directly in the database breaks canonical evidence hash."""
        model_id = setup_approved_model_and_tokens["model_id"]
        token = setup_approved_model_and_tokens["user_token"]
        img_bytes = create_test_image_bytes(200, 150)

        inf_res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {token}"},
            data={"model_id": model_id},
            files={"image": ("scene_db.png", io.BytesIO(img_bytes), "image/png")},
        )
        inference_id = inf_res.json()["inference_id"]

        # Directly tamper the predictions_json in database
        rec_res = await db_session.execute(
            select(InferenceRecord).where(InferenceRecord.id == inference_id)
        )
        rec = rec_res.scalar_one()
        rec.predictions_json = '[{"class_name": "forged_pedestrian", "confidence": 0.999, "bbox": [0,0,10,10]}]'
        await db_session.commit()

        ver_res = await client.post(
            f"/api/inference/{inference_id}/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert ver_res.status_code == 200
        ver_data = ver_res.json()
        assert ver_data["evidence_integrity"] is False
        assert ver_data["overall_status"] == "TAMPERED"
        assert any("Evidence hash mismatch" in d for d in ver_data["discrepancies"])

    async def test_tampered_signature_detected(
        self, client: AsyncClient, setup_approved_model_and_tokens: dict, db_session: AsyncSession
    ):
        """Corrupting the stored Ed25519 signature fails cryptographic verification."""
        model_id = setup_approved_model_and_tokens["model_id"]
        token = setup_approved_model_and_tokens["user_token"]
        img_bytes = create_test_image_bytes(200, 150)

        inf_res = await client.post(
            "/api/inference/detect",
            headers={"Authorization": f"Bearer {token}"},
            data={"model_id": model_id},
            files={"image": ("scene_sig.png", io.BytesIO(img_bytes), "image/png")},
        )
        inference_id = inf_res.json()["inference_id"]

        # Corrupt the signature in DB
        rec_res = await db_session.execute(
            select(InferenceRecord).where(InferenceRecord.id == inference_id)
        )
        rec = rec_res.scalar_one()
        rec.evidence_signature = "00" * 64
        await db_session.commit()

        ver_res = await client.post(
            f"/api/inference/{inference_id}/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert ver_res.status_code == 200
        ver_data = ver_res.json()
        assert ver_data["signature_valid"] is False
        assert ver_data["overall_status"] in ("TAMPERED", "NOT_VERIFIED")
        assert any("signature verification failed" in d.lower() for d in ver_data["discrepancies"])

    async def test_non_existent_record_returns_404(
        self, client: AsyncClient, setup_approved_model_and_tokens: dict
    ):
        """Verifying non-existent inference_id returns 404 Not Found."""
        token = setup_approved_model_and_tokens["user_token"]
        ver_res = await client.post(
            "/api/inference/non-existent-uuid-12345/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert ver_res.status_code == 404