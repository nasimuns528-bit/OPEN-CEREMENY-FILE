"""
Phase 7 Tests — Trust Dashboard and Integrity Assurance Scoring Engine.
Verifies:
1. Retrieval of real-time 0-100 Integrity Assurance Score and 6 scoring components.
2. Verified presence of explicit correctness disclaimer.
3. Pipeline summaries (datasets, models, inference, audit chain).
4. Rejection of unauthenticated requests (401 or 403).
5. Dynamic score degradation and alert generation when assets are tampered.
"""
import uuid
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dataset import Dataset, DatasetVersion
from app.models.user import User


@pytest.fixture
async def auth_user_token(client: AsyncClient) -> str:
    await client.post(
        "/api/auth/register",
        json={
            "username": "dash_reviewer",
            "email": "dash_reviewer@example.com",
            "password": "ReviewerPass1",
            "role": "REVIEWER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "dash_reviewer", "password": "ReviewerPass1"},
    )
    return res.json()["access_token"]


@pytest.mark.asyncio
class TestTrustDashboard:
    async def test_get_dashboard_metrics_success(
        self, client: AsyncClient, auth_user_token: str
    ):
        """Authenticated user receives structured metrics with 6-pillar breakdown and disclaimer."""
        res = await client.get(
            "/api/dashboard/metrics",
            headers={"Authorization": f"Bearer {auth_user_token}"},
        )
        assert res.status_code == 200
        data = res.json()

        # Score & Disclaimer validation
        assert 0.0 <= data["assurance_score"] <= 100.0
        assert data["label"] == "Integrity Assurance Score"
        assert data["rating"] in ("HIGH ASSURANCE", "MODERATE ASSURANCE", "COMPROMISED")
        assert "not mathematical proof of ai correctness" in data["disclaimer"].lower()

        # 6-Component Breakdown
        breakdown = data["scoring_breakdown"]
        assert len(breakdown) == 6
        expected_keys = {
            "data_integrity",
            "model_integrity",
            "provenance_chain",
            "contributor_trust",
            "inference_evidence",
            "security_scanning",
        }
        actual_keys = {c["key"] for c in breakdown}
        assert actual_keys == expected_keys

        for comp in breakdown:
            assert comp["score"] <= comp["max_score"]
            assert comp["status"] in ("OPTIMAL", "ATTENTION", "DEGRADED")
            assert len(comp["explanation"]) > 0

        # Pipeline Summaries
        assert "total_datasets" in data["datasets_summary"]
        assert "total_models" in data["models_summary"]
        assert "total_inferences" in data["inference_summary"]
        assert "is_valid" in data["audit_chain_status"]

    async def test_unauthenticated_request_rejected(self, client: AsyncClient):
        """Unauthenticated requests to /api/dashboard/metrics receive 401 or 403."""
        res = await client.get("/api/dashboard/metrics")
        assert res.status_code in (401, 403)

    async def test_tampered_dataset_triggers_alert_and_score_degradation(
        self, client: AsyncClient, auth_user_token: str, db_session: AsyncSession
    ):
        """Marking a dataset version as TAMPERED reduces score and raises a CRITICAL alert."""
        # 1. Fetch baseline metrics
        base_res = await client.get(
            "/api/dashboard/metrics",
            headers={"Authorization": f"Bearer {auth_user_token}"},
        )
        base_score = base_res.json()["assurance_score"]
        base_alerts = base_res.json()["active_alerts_count"]

        # 2. Inject a tampered dataset version in DB using db_session
        u_res = await db_session.execute(select(User).where(User.username == "dash_reviewer"))
        user = u_res.scalar_one()

        ds = Dataset(
            id=str(uuid.uuid4()),
            name="Tamper Test Dataset",
            description="Test dataset for dashboard alert verification",
            owner_id=user.id,
            owner_username=user.username,
        )
        db_session.add(ds)
        await db_session.flush()

        dv = DatasetVersion(
            id=str(uuid.uuid4()),
            dataset_id=ds.id,
            version_tag="v_compromised",
            file_count=1,
            total_size=100,
            dataset_hash="00" * 32,
            created_by_id=user.id,
            created_by_username=user.username,
            status="TAMPERED",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(dv)
        await db_session.commit()

        # 3. Re-fetch metrics
        new_res = await client.get(
            "/api/dashboard/metrics",
            headers={"Authorization": f"Bearer {auth_user_token}"},
        )
        assert new_res.status_code == 200
        new_data = new_res.json()

        # Active alert generated
        assert new_data["active_alerts_count"] >= base_alerts + 1
        alerts = new_data["security_alerts"]
        tampered_alerts = [a for a in alerts if a["category"] == "DATASET" and a["severity"] == "CRITICAL"]
        assert len(tampered_alerts) > 0

        # Data integrity status degraded
        data_comp = next(c for c in new_data["scoring_breakdown"] if c["key"] == "data_integrity")
        assert data_comp["status"] == "DEGRADED"