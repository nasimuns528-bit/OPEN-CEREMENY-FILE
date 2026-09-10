"""
VisionTrust — Local & Hackathon Demo Seeding Script
Populates the database with default demo accounts across all 5 RBAC roles,
an initial Genesis audit log root, and baseline clean demo assets.
Run with:
    python -m scripts.seed_demo
"""
from __future__ import annotations

import asyncio
import io
import sys
from pathlib import Path

# Add backend root to path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from sqlalchemy import select
from app.core.database import AsyncSessionLocal, engine, Base
from app.models.user import User
from app.models.dataset import Dataset, DatasetVersion, DatasetFile
from app.models.model import Model, ModelVersion, ModelSecurityScan
from app.models.audit import AuditEvent
from app.security.hashing import hash_password
from app.security.ed25519 import get_or_create_ed25519_keypair, sign_model_metadata
from app.services.audit_service import GENESIS_HASH
from app.utils.storage import compute_sha256_bytes, UPLOAD_BASE_DIR

DEMO_USERS = [
    {
        "username": "admin",
        "email": "admin@visiontrust.local",
        "password": "DemoAdmin2026!",
        "role": "ADMIN",
    },
    {
        "username": "alice_data",
        "email": "alice@visiontrust.local",
        "password": "DemoUser2026!",
        "role": "DATA_CONTRIBUTOR",
    },
    {
        "username": "bob_models",
        "email": "bob@visiontrust.local",
        "password": "DemoUser2026!",
        "role": "MODEL_CONTRIBUTOR",
    },
    {
        "username": "carol_review",
        "email": "carol@visiontrust.local",
        "password": "DemoUser2026!",
        "role": "REVIEWER",
    },
    {
        "username": "dave_infer",
        "email": "dave@visiontrust.local",
        "password": "DemoUser2026!",
        "role": "INFERENCE_USER",
    },
]


async def seed():
    print("=" * 60)
    print("VisionTrust Database Seeder — Initializing Demo Assets")
    print("=" * 60)

    # Ensure tables exist
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except (OSError, Exception) as conn_err:
        print(f"\n[!] Database connection failed: {conn_err}")
        print("[!] If running locally with Docker: run 'docker compose up db -d'")
        print("[!] Or for standalone SQLite demo: set DATABASE_URL=sqlite+aiosqlite:///./visiontrust.db in backend/.env")
        return

    async with AsyncSessionLocal() as db:
        # 1. Seed Users
        created_users = {}
        for u_data in DEMO_USERS:
            res = await db.execute(select(User).where(User.username == u_data["username"]))
            existing = res.scalar_one_or_none()
            if not existing:
                user = User(
                    username=u_data["username"],
                    email=u_data["email"],
                    hashed_password=hash_password(u_data["password"]),
                    role=u_data["role"],
                    is_active=True,
                )
                db.add(user)
                await db.flush()
                created_users[u_data["role"]] = user
                print(f"[+] Created user: {u_data['username']} ({u_data['role']})")
            else:
                created_users[u_data["role"]] = existing
                print(f"[*] User already exists: {u_data['username']} ({u_data['role']})")

        # 2. Seed Genesis Audit Event if empty
        audit_res = await db.execute(select(AuditEvent).limit(1))
        if not audit_res.scalar_one_or_none():
            genesis_event = AuditEvent(
                sequence_number=1,
                action="SYSTEM_INIT_GENESIS",
                resource_type="system",
                resource_id="genesis",
                actor_id=created_users["ADMIN"].id,
                actor_username="admin",
                ip_address="127.0.0.1",
                details='{"status": "initialized", "chain": "VisionTrust-Main"}',
                previous_event_hash=GENESIS_HASH,
                current_hash=compute_sha256_bytes(
                    f"1|SYSTEM_INIT_GENESIS|system|genesis|admin|{GENESIS_HASH}".encode()
                ),
            )
            db.add(genesis_event)
            print("[+] Initialized Genesis block in audit chain")

        # 3. Seed Baseline Demo Dataset
        ds_res = await db.execute(select(Dataset).where(Dataset.name == "urban_traffic_v1"))
        if not ds_res.scalar_one_or_none():
            alice = created_users["DATA_CONTRIBUTOR"]
            demo_ds = Dataset(
                name="urban_traffic_v1",
                description="Standard urban traffic object detection benchmark dataset with vehicle & pedestrian annotations.",
                owner_id=alice.id,
                owner_username=alice.username,
                status="VERIFIED",
                current_version="v1.0",
                current_hash="4a5c6e8f9b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f",
            )
            db.add(demo_ds)
            await db.flush()

            # Create version
            v1 = DatasetVersion(
                dataset_id=demo_ds.id,
                version_tag="v1.0",
                dataset_hash=demo_ds.current_hash,
                file_count=2,
                total_size=102400,
                created_by_id=alice.id,
                created_by_username=alice.username,
            )
            db.add(v1)
            await db.flush()

            # Ensure dataset upload directory exists and create dummy sample image binaries
            ds_upload_dir = UPLOAD_BASE_DIR / "datasets" / demo_ds.id
            ds_upload_dir.mkdir(parents=True, exist_ok=True)
            f1_path = ds_upload_dir / "demo_traffic_01.jpg"
            f2_path = ds_upload_dir / "demo_pedestrian_02.jpg"
            f1_path.write_bytes(b"\xff\xd8\xff\xe0DEMO_TRAFFIC_IMAGE_BINARY_01")
            f2_path.write_bytes(b"\xff\xd8\xff\xe0DEMO_PEDESTRIAN_IMAGE_BINARY_02")

            # Create files
            f1 = DatasetFile(
                dataset_id=demo_ds.id,
                version_id=v1.id,
                original_filename="traffic_intersection_01.jpg",
                storage_name="demo_traffic_01.jpg",
                storage_path=str(f1_path),
                file_size=len(f1_path.read_bytes()),
                mime_type="image/jpeg",
                sha256_hash=compute_sha256_bytes(f1_path.read_bytes()),
                uploaded_by_id=alice.id,
                uploaded_by_username=alice.username,
            )
            f2 = DatasetFile(
                dataset_id=demo_ds.id,
                version_id=v1.id,
                original_filename="pedestrian_crossing_02.jpg",
                storage_name="demo_pedestrian_02.jpg",
                storage_path=str(f2_path),
                file_size=len(f2_path.read_bytes()),
                mime_type="image/jpeg",
                sha256_hash=compute_sha256_bytes(f2_path.read_bytes()),
                uploaded_by_id=alice.id,
                uploaded_by_username=alice.username,
            )
            db.add_all([f1, f2])
            print("[+] Seeded demo dataset 'urban_traffic_v1' with version v1.0")

        # 4. Seed Baseline Approved Model
        m_res = await db.execute(select(Model).where(Model.name == "yolov8_detector_v1"))
        if not m_res.scalar_one_or_none():
            bob = created_users["MODEL_CONTRIBUTOR"]
            carol = created_users["REVIEWER"]

            demo_model = Model(
                name="yolov8_detector_v1",
                description="Pre-trained verified YOLOv8 detector optimized for traffic & pedestrian visual recognition.",
                framework="YOLOv8",
                model_type="object_detection",
                owner_id=bob.id,
                owner_username=bob.username,
            )
            db.add(demo_model)
            await db.flush()

            # Create physical weights file in uploads/models
            model_storage_dir = UPLOAD_BASE_DIR / "models"
            model_storage_dir.mkdir(parents=True, exist_ok=True)
            model_weights_path = model_storage_dir / f"{demo_model.id}_v1.0.bin"
            model_content = b"VISIONTRUST_APPROVED_YOLOV8_WEIGHTS_BINARY_PAYLOAD_V1.0"
            model_weights_path.write_bytes(model_content)
            model_hash = compute_sha256_bytes(model_content)

            # Generate Reviewer Ed25519 Signature
            priv_key, pub_hex = get_or_create_ed25519_keypair()
            reviewer_sig = sign_model_metadata(
                private_key=priv_key,
                model_id=demo_model.id,
                version_tag="v1.0",
                model_hash=model_hash,
                associated_dataset_version=None,
                approval_status="APPROVED",
            )

            mv = ModelVersion(
                model_id=demo_model.id,
                version_tag="v1.0",
                model_format=".bin",
                file_size=len(model_content),
                sha256_hash=model_hash,
                storage_name=f"{demo_model.id}_v1.0.bin",
                storage_path=str(model_weights_path),
                contributor_id=bob.id,
                contributor_username=bob.username,
                approval_status="APPROVED",
                approved_by_id=carol.id,
                approved_by_username=carol.username,
                security_scan_status="PASSED",
                ed25519_signature=reviewer_sig,
                ed25519_public_key=pub_hex,
            )
            db.add(mv)
            await db.flush()

            # Add Scan Record
            scan = ModelSecurityScan(
                model_version_id=mv.id,
                scan_result="CLEAN",
                findings_json="[]",
            )
            db.add(scan)
            print("[+] Seeded approved model 'yolov8_detector_v1' with Ed25519 signature")

        await db.commit()

    print("\n" + "=" * 60)
    print("Demo Seeding Complete! Registered Demo Accounts:")
    print("-" * 60)
    for u in DEMO_USERS:
        print(f"Role: {u['role']:<18} User: {u['username']:<15} Pass: {u['password']}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(seed())
