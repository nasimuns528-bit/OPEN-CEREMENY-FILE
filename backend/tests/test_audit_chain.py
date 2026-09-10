"""
Phase 3 — Multi-Contributor Provenance & Tamper-Evident Hash Chain Tests.
Verifies:
- Append-only audit chain creation with monotonic sequence numbers
- Cryptographic hash chaining back to GENESIS root
- Chain verification endpoint (POST /api/audit/verify)
- Controlled tamper test: modify an audit event row in the database, confirm that POST /api/audit/verify fails and pinpoints the corrupted event
- Role authorization: Reviewer/Admin can verify chain; Inference users cannot tamper with audit logs
"""
import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent
from app.services.audit_service import GENESIS_HASH, log_event, verify_audit_chain


@pytest.fixture
async def reviewer_token(client: AsyncClient) -> str:
    """Register and login a REVIEWER."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "reviewer_audit",
            "email": "reviewer_audit@example.com",
            "password": "ReviewerPass1",
            "role": "REVIEWER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "reviewer_audit", "password": "ReviewerPass1"},
    )
    return res.json()["access_token"]


@pytest.fixture
async def inference_token(client: AsyncClient) -> str:
    """Register and login an INFERENCE_USER."""
    await client.post(
        "/api/auth/register",
        json={
            "username": "infer_audit",
            "email": "infer_audit@example.com",
            "password": "InferPass1",
            "role": "INFERENCE_USER",
        },
    )
    res = await client.post(
        "/api/auth/login",
        json={"username": "infer_audit", "password": "InferPass1"},
    )
    return res.json()["access_token"]


@pytest.mark.asyncio
class TestAuditChainProvenance:
    async def test_audit_event_hash_chain_creation(self, db_session: AsyncSession):
        """Events are chained with previous_event_hash and monotonically increasing sequences."""
        ev1 = await log_event(
            db_session,
            action="DATASET_CREATED",
            actor_id="user-1",
            actor_username="alice",
            resource_type="dataset",
            resource_id="ds-1",
            previous_state=None,
            new_state="ACTIVE",
        )
        await db_session.commit()

        ev2 = await log_event(
            db_session,
            action="FILE_UPLOADED",
            actor_id="user-1",
            actor_username="alice",
            resource_type="file",
            resource_id="file-1",
            previous_state=None,
            new_state="STORED",
        )
        await db_session.commit()

        # Sequence numbers must be strictly ordered
        assert ev2.sequence_number > ev1.sequence_number
        # ev2 previous_event_hash must match ev1's current_hash
        assert ev2.previous_event_hash == ev1.current_hash
        # Hashes must be 64-character SHA-256 hex digests
        assert len(ev1.current_hash) == 64
        assert len(ev2.current_hash) == 64

    async def test_verify_valid_audit_chain_endpoint(
        self, client: AsyncClient, reviewer_token: str
    ):
        """POST /api/audit/verify returns valid: True when chain is untampered."""
        res = await client.post(
            "/api/audit/verify",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["valid"] is True
        assert data["events_checked"] >= 0
        assert data["first_invalid_event"] is None

    async def test_inference_user_cannot_verify_chain(
        self, client: AsyncClient, inference_token: str
    ):
        """INFERENCE_USER is forbidden from running administrative chain verification."""
        res = await client.post(
            "/api/audit/verify",
            headers={"Authorization": f"Bearer {inference_token}"},
        )
        assert res.status_code == 403

    async def test_controlled_audit_tamper_detection(
        self, client: AsyncClient, reviewer_token: str, db_session: AsyncSession
    ):
        """
        CONTROLLED AUDIT TAMPER TEST:
        1. Log several audit events to build a valid chain.
        2. Intentionally modify a historical row in the database (alter action or metadata).
        3. Call POST /api/audit/verify.
        4. Confirm that:
           - valid is False
           - first_invalid_event matches the tampered record
           - tamper_details describes the detected discrepancy
        """
        # 1. Create a series of distinct audit events
        e1 = await log_event(
            db_session,
            action="DATASET_CREATED",
            actor_id="actor-1",
            actor_username="contributor1",
            resource_type="dataset",
            resource_id="ds-tamper-test",
            previous_state=None,
            new_state="ACTIVE",
            details={"name": "Tamper Test Target"},
        )
        e2 = await log_event(
            db_session,
            action="DATASET_VERSION_CREATED",
            actor_id="actor-1",
            actor_username="contributor1",
            resource_type="dataset",
            resource_id="ds-tamper-test",
            version_tag="v1.0",
            previous_state="ACTIVE",
            new_state="v1.0",
        )
        e3 = await log_event(
            db_session,
            action="DATASET_VERIFIED",
            actor_id="actor-2",
            actor_username="reviewer1",
            resource_type="dataset",
            resource_id="ds-tamper-test",
            previous_state="ACTIVE",
            new_state="VERIFIED",
        )
        await db_session.commit()

        # Chain is currently valid
        valid_before, _, _, _, _ = await verify_audit_chain(db_session)
        assert valid_before is True

        # 2. MALICIOUSLY ALTER HISTORICAL ROW IN DATABASE
        # e.g., an attacker directly changes action from DATASET_CREATED to UNAUTHORIZED_OVERWRITE
        await db_session.execute(
            update(AuditEvent)
            .where(AuditEvent.id == e1.id)
            .values(action="ALTERED_BY_MALICIOUS_DBA")
        )
        await db_session.commit()

        # 3. Cryptographic chain verification must detect the modification!
        verify_res = await client.post(
            "/api/audit/verify",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert verify_res.status_code == 200
        result = verify_res.json()

        # 4. Verification must fail and flag the exact corrupt event
        assert result["valid"] is False
        assert result["first_invalid_event"] == e1.id
        assert "mismatch" in result["tamper_details"].lower()
