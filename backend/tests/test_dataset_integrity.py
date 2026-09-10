"""
Phase 2 — Comprehensive Dataset Integrity & Tamper Detection Tests.
Verifies:
- Dataset creation by authorized roles (DATA_CONTRIBUTOR, ADMIN) and rejection for others
- Secure file upload, extension validation, path traversal filename sanitization
- Deterministic composite SHA-256 dataset hash calculation
- Dataset version freezing and metadata tracking
- Cryptographic integrity verification on untouched files
- Controlled tampering detection (modifying physical file on disk produces EXPECTED HASH != CURRENT HASH and TAMPERED status)
"""
import io
from pathlib import Path
import pytest
from httpx import AsyncClient
from app.utils.storage import UPLOAD_BASE_DIR, compute_file_hash_on_disk


@pytest.fixture
async def contributor_token(client: AsyncClient) -> str:
    """Register and login a DATA_CONTRIBUTOR."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "datacontrib",
            "email": "datacontrib@example.com",
            "password": "DataContribPass1",
            "role": "DATA_CONTRIBUTOR",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "datacontrib", "password": "DataContribPass1"},
    )
    return res.json()["access_token"]


@pytest.fixture
async def reviewer_token(client: AsyncClient) -> str:
    """Register and login a REVIEWER."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "reviewer1",
            "email": "reviewer1@example.com",
            "password": "ReviewerPass1",
            "role": "REVIEWER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "reviewer1", "password": "ReviewerPass1"},
    )
    return res.json()["access_token"]


@pytest.fixture
async def inference_token(client: AsyncClient) -> str:
    """Register and login an INFERENCE_USER."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "inferuser",
            "email": "inferuser@example.com",
            "password": "InferPass1",
            "role": "INFERENCE_USER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "inferuser", "password": "InferPass1"},
    )
    return res.json()["access_token"]


@pytest.mark.asyncio
class TestDatasetIntegrity:
    async def test_create_dataset_authorized(self, client: AsyncClient, contributor_token: str):
        """Authorized DATA_CONTRIBUTOR can create a dataset."""
        res = await client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"name": "Traffic Camera Dataset", "description": "Urban vehicle detection frames"},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["name"] == "Traffic Camera Dataset"
        assert data["owner_username"] == "datacontrib"
        assert data["status"] == "ACTIVE"
        assert "id" in data

    async def test_create_dataset_unauthorized_role(self, client: AsyncClient, inference_token: str):
        """INFERENCE_USER cannot create datasets (403 Forbidden)."""
        res = await client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {inference_token}"},
            json={"name": "Forbidden Dataset"},
        )
        assert res.status_code == 403

    async def test_upload_valid_file_and_hash_calculation(
        self, client: AsyncClient, contributor_token: str
    ):
        """Upload valid image file, verify SHA-256 hash calculation."""
        # 1. Create dataset
        c_res = await client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"name": "Object Detection v1"},
        )
        dataset_id = c_res.json()["id"]

        # 2. Upload file
        file_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRtest_image_bytes"
        files = {"files": ("sample1.png", io.BytesIO(file_content), "image/png")}
        up_res = await client.post(
            f"/api/datasets/{dataset_id}/files",
            headers={"Authorization": f"Bearer {contributor_token}"},
            files=files,
        )
        assert up_res.status_code == 201
        uploaded = up_res.json()
        assert len(uploaded) == 1
        assert uploaded[0]["original_filename"] == "sample1.png"
        assert len(uploaded[0]["sha256_hash"]) == 64
        # Verify hash matches sha256 of file_content
        import hashlib
        expected_hash = hashlib.sha256(file_content).hexdigest()
        assert uploaded[0]["sha256_hash"] == expected_hash

    async def test_reject_forbidden_file_extension(
        self, client: AsyncClient, contributor_token: str
    ):
        """Disallowed extensions (.exe, .sh, etc.) are rejected."""
        c_res = await client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"name": "Executable Test"},
        )
        dataset_id = c_res.json()["id"]

        files = {"files": ("exploit.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")}
        res = await client.post(
            f"/api/datasets/{dataset_id}/files",
            headers={"Authorization": f"Bearer {contributor_token}"},
            files=files,
        )
        assert res.status_code == 400
        assert "forbidden" in res.json()["detail"].lower()

    async def test_path_traversal_filename_sanitization(
        self, client: AsyncClient, contributor_token: str
    ):
        """Malicious filenames like '../../etc/passwd' are sanitized and safely stored."""
        c_res = await client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"name": "Path Traversal Dataset"},
        )
        dataset_id = c_res.json()["id"]

        malicious_filename = "../../../../etc/shadow.png"
        files = {"files": (malicious_filename, io.BytesIO(b"\x89PNG\r\n\x1a\nsafe_data"), "image/png")}
        res = await client.post(
            f"/api/datasets/{dataset_id}/files",
            headers={"Authorization": f"Bearer {contributor_token}"},
            files=files,
        )
        assert res.status_code == 201
        saved_file = res.json()[0]
        # Should not contain path traversal indicators
        assert ".." not in saved_file["original_filename"]
        assert "/" not in saved_file["original_filename"]
        assert "\\" not in saved_file["original_filename"]

    async def test_version_creation_deterministic_hash(
        self, client: AsyncClient, contributor_token: str
    ):
        """Creating a version computes a deterministic composite hash over all files."""
        c_res = await client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"name": "Versioned Dataset"},
        )
        dataset_id = c_res.json()["id"]

        # Upload two files
        f1_data = b"\x89PNG\r\n\x1a\nframe_001"
        f2_data = b"\x89PNG\r\n\x1a\nframe_002"
        await client.post(
            f"/api/datasets/{dataset_id}/files",
            headers={"Authorization": f"Bearer {contributor_token}"},
            files={"files": ("b_frame.png", io.BytesIO(f1_data), "image/png")},
        )
        await client.post(
            f"/api/datasets/{dataset_id}/files",
            headers={"Authorization": f"Bearer {contributor_token}"},
            files={"files": ("a_frame.png", io.BytesIO(f2_data), "image/png")},
        )

        # Freeze version
        v_res = await client.post(
            f"/api/datasets/{dataset_id}/versions",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"version_tag": "v1.0"},
        )
        assert v_res.status_code == 201
        v_data = v_res.json()
        assert v_data["version_tag"] == "v1.0"
        assert v_data["file_count"] == 2
        assert len(v_data["dataset_hash"]) == 64

    async def test_integrity_verification_unmodified_files(
        self, client: AsyncClient, contributor_token: str, reviewer_token: str
    ):
        """Untouched files pass verification with status VERIFIED."""
        c_res = await client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"name": "Verified Dataset"},
        )
        dataset_id = c_res.json()["id"]

        await client.post(
            f"/api/datasets/{dataset_id}/files",
            headers={"Authorization": f"Bearer {contributor_token}"},
            files={"files": ("cam1.jpg", io.BytesIO(b"\xff\xd8\xffframe"), "image/jpeg")},
        )
        await client.post(
            f"/api/datasets/{dataset_id}/versions",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"version_tag": "v1.0"},
        )

        # Reviewer verifies
        verify_res = await client.post(
            f"/api/datasets/{dataset_id}/verify",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert verify_res.status_code == 200
        verify_data = verify_res.json()
        assert verify_data["status"] == "VERIFIED"
        assert verify_data["tampered_files_count"] == 0
        assert verify_data["file_results"][0]["status"] == "VERIFIED"

    async def test_controlled_tampering_detection(
        self, client: AsyncClient, contributor_token: str, reviewer_token: str
    ):
        """
        CONTROLLED TAMPER TEST:
        Intentionally modify a file's physical content on disk.
        Verify that:
        1. EXPECTED HASH != CURRENT HASH
        2. Status becomes TAMPERED
        3. Audit trail records DATASET_TAMPER_DETECTED
        """
        # 1. Create dataset and upload a file
        c_res = await client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"name": "Tamper Test Dataset"},
        )
        dataset_id = c_res.json()["id"]

        orig_bytes = b"\x89PNG\r\n\x1a\noriginal_untampered_content"
        up_res = await client.post(
            f"/api/datasets/{dataset_id}/files",
            headers={"Authorization": f"Bearer {contributor_token}"},
            files={"files": ("evidence.png", io.BytesIO(orig_bytes), "image/png")},
        )
        file_info = up_res.json()[0]
        expected_hash = file_info["sha256_hash"]

        # Freeze version
        await client.post(
            f"/api/datasets/{dataset_id}/versions",
            headers={"Authorization": f"Bearer {contributor_token}"},
            json={"version_tag": "v1.0"},
        )

        # 2. Get file details to locate disk file
        detail_res = await client.get(
            f"/api/datasets/{dataset_id}",
            headers={"Authorization": f"Bearer {contributor_token}"},
        )
        storage_name = detail_res.json()["files"][0]["storage_name"]
        disk_path = UPLOAD_BASE_DIR / "datasets" / dataset_id / storage_name
        assert disk_path.exists(), f"File should exist at {disk_path}"

        # 3. INTENTIONALLY TAMPER FILE CONTENT ON DISK
        tampered_bytes = b"\x89PNG\r\n\x1a\nMALICIOUS_INJECTED_TAMPERED_BYTES"
        with open(disk_path, "wb") as f:
            f.write(tampered_bytes)

        # Verify disk hash is now different
        current_disk_hash = compute_file_hash_on_disk(disk_path)
        assert expected_hash != current_disk_hash, "Sanity check: Disk content must differ"

        # 4. Run verification endpoint
        verify_res = await client.post(
            f"/api/datasets/{dataset_id}/verify",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert verify_res.status_code == 200
        result = verify_res.json()

        # 5. Assert EXPECTED HASH != CURRENT HASH and status == TAMPERED
        assert result["status"] == "TAMPERED"
        assert result["tampered_files_count"] == 1
        file_result = result["file_results"][0]
        assert file_result["status"] == "TAMPERED"
        assert file_result["expected_hash"] == expected_hash
        assert file_result["current_hash"] == current_disk_hash
        assert file_result["expected_hash"] != file_result["current_hash"]

        # 6. Check dataset state was updated
        updated_dataset = (
            await client.get(
                f"/api/datasets/{dataset_id}",
                headers={"Authorization": f"Bearer {contributor_token}"},
            )
        ).json()
        assert updated_dataset["status"] == "TAMPERED"

        # 7. Check that DATASET_TAMPER_DETECTED audit event was logged
        audit_res = await client.get(
            f"/api/audit?action=DATASET_TAMPER_DETECTED",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert audit_res.status_code == 200
        events = audit_res.json()
        assert len(events) >= 1
        tamper_event = events[0]
        assert tamper_event["action"] == "DATASET_TAMPER_DETECTED"
        assert tamper_event["new_state"] == "TAMPERED"
