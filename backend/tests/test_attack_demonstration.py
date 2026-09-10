"""
Phase 8 Automated Tests — Controlled Integrity Attack Demonstrations.
Verifies all 4 controlled demonstration workflows on isolated test assets:
1. Attack 1: Dataset file modification detecting DATA INTEGRITY FAILURE
2. Attack 2: Model weights alteration detecting MODEL INTEGRITY FAILURE & blocking inference
3. Attack 3: Inference output modification detecting INFERENCE EVIDENCE INVALID
4. Attack 4: Audit chain alteration detecting AUDIT CHAIN INVALID
5. RBAC security: Unauthorized roles (e.g. INFERENCE_USER) receive 403 Forbidden
"""
import pytest
from httpx import AsyncClient


@pytest.fixture
async def reviewer_token(client: AsyncClient) -> str:
    await client.post(
        "/api/auth/register",
        json={
            "username": "demo_reviewer_ops",
            "email": "demo_reviewer_ops@example.com",
            "password": "ReviewerPass1",
            "role": "REVIEWER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "demo_reviewer_ops", "password": "ReviewerPass1"},
    )
    return res.json()["access_token"]


@pytest.fixture
async def inference_user_token(client: AsyncClient) -> str:
    await client.post(
        "/api/auth/register",
        json={
            "username": "demo_plain_user",
            "email": "demo_plain_user@example.com",
            "password": "UserPass123",
            "role": "INFERENCE_USER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "demo_plain_user", "password": "UserPass123"},
    )
    return res.json()["access_token"]


@pytest.mark.asyncio
class TestAttackDemonstrations:
    async def test_attack_1_dataset_tampering_workflow(
        self, client: AsyncClient, reviewer_token: str
    ):
        """Attack 1 creates test dataset, alters disk bytes, detects mismatch and displays DATA INTEGRITY FAILURE."""
        res = await client.post(
            "/api/demonstration/attack-1-dataset-tamper",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()

        assert data["scenario_id"] == "attack_1_dataset"
        assert data["display_title"] == "DATA INTEGRITY FAILURE"
        assert data["tamper_detected"] is True
        assert len(data["steps"]) >= 5
        assert "original_sha256" in data["telemetry"]
        assert "tampered_sha256" in data["telemetry"]
        assert data["telemetry"]["original_sha256"] != data["telemetry"]["tampered_sha256"]

    async def test_attack_2_model_tampering_workflow(
        self, client: AsyncClient, reviewer_token: str
    ):
        """Attack 2 alters approved model weights on disk, detects hash mismatch and blocks inference."""
        res = await client.post(
            "/api/demonstration/attack-2-model-tamper",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()

        assert data["scenario_id"] == "attack_2_model"
        assert data["display_title"] == "MODEL INTEGRITY FAILURE"
        assert data["inference_status"] == "INFERENCE BLOCKED"
        assert data["tamper_detected"] is True
        assert len(data["steps"]) >= 4
        assert "block_reason" in data["telemetry"]

    async def test_attack_3_inference_output_tampering_workflow(
        self, client: AsyncClient, reviewer_token: str
    ):
        """Attack 3 alters stored bounding box predictions in DB and detects INFERENCE EVIDENCE INVALID."""
        res = await client.post(
            "/api/demonstration/attack-3-inference-tamper",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()

        assert data["scenario_id"] == "attack_3_inference"
        assert data["display_title"] == "INFERENCE EVIDENCE INVALID"
        assert data["tamper_detected"] is True
        assert len(data["steps"]) >= 4
        assert data["telemetry"]["overall_status"] in ("TAMPERED", "NOT_VERIFIED")

    async def test_attack_4_audit_chain_tampering_workflow(
        self, client: AsyncClient, reviewer_token: str
    ):
        """Attack 4 modifies historical audit record in DB and detects AUDIT CHAIN INVALID."""
        res = await client.post(
            "/api/demonstration/attack-4-audit-tamper",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()

        assert data["scenario_id"] == "attack_4_audit"
        assert data["display_title"] == "AUDIT CHAIN INVALID"
        assert data["tamper_detected"] is True
        assert len(data["steps"]) >= 3
        assert data["telemetry"]["chain_status"] == "BROKEN"

    async def test_unauthorized_user_blocked_from_demonstrations(
        self, client: AsyncClient, inference_user_token: str
    ):
        """Non-reviewer / non-admin users receive 403 Forbidden when calling demonstration endpoints."""
        res = await client.post(
            "/api/demonstration/attack-1-dataset-tamper",
            headers={"Authorization": f"Bearer {inference_user_token}"},
        )
        assert res.status_code == 403

    async def test_get_scenarios_list(
        self, client: AsyncClient, reviewer_token: str
    ):
        """Authorized user can query available demonstration scenarios."""
        res = await client.get(
            "/api/demonstration/scenarios",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert res.status_code == 200
        scenarios = res.json()
        assert len(scenarios) == 4
        expected_ids = {"attack_1_dataset", "attack_2_model", "attack_3_inference", "attack_4_audit"}
        assert {s["id"] for s in scenarios} == expected_ids