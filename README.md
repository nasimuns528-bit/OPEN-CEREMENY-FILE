# VISIONTRUST

> **Trustworthy Computer Vision Integrity Assurance for Data, Models, and Inference Outputs in Multi-Contributor Pipelines**

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/framework-FastAPI-0058e0.svg)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/frontend-React%2019-61dafb.svg)](https://react.dev/)
[![Tests](https://img.shields.io/badge/tests-96%20passed-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

---

## 1. Problem Statement

In modern distributed AI pipelines, Computer Vision models are built and deployed collaboratively across disparate organizations and contributors. This decentralization introduces critical security and trust vulnerabilities:

1. **Dataset Poisoning & Silent Tampering**: Malicious contributors can alter images or labels after review, invalidating training provenance and injecting backdoors without detection.
2. **Trojaned Models & Weight Replacement**: Attackers can swap approved model weights with trojaned versions or introduce deserialization exploits (e.g., malicious Python Pickle payloads) that achieve remote code execution (RCE).
3. **Inference Output Fabrication & Disputed Detections**: Detection results and safety audits can be forged, manipulated, or repudiated without cryptographic proof linking the exact input image, model hash, and execution timestamp.
4. **Audit Trail Destruction**: Centralized database logs can be rewritten, truncated, or retroactively modified to conceal unauthorized pipeline changes.

---

## 2. Motivation

VisionTrust bridges the gap between Computer Vision operations and zero-trust cybersecurity. Rather than trusting pipeline assets implicitly, VisionTrust treats **data, models, and inference outputs as cryptographically verifiable artifacts**.

By enforcing streaming SHA-256 digests, Ed25519 digital signatures, static bytecode inspection, canonical deterministic evidence generation, and an append-only chained audit ledger with a Genesis root anchor, VisionTrust ensures that any unauthorized modification is deterministically detected and blocked.

---

## 3. Architecture

VisionTrust implements an end-to-end cryptographic trust chain:

```
[ Contributor Image ] ──► Streaming SHA-256 ──► Immutable Dataset Version (Composite Tree)
                                                         │
                                                  Genesis Audit Chain
                                                         │
[ Model Weights File ] ──► Static Opcode Scan ──► Reviewer Ed25519 Signature (Approved)
                                                         │
[ Inference Query ] ──► Pre-flight Eligibility ──► OpenCV Object Detection
                                                         │
                                             Canonical Evidence (RFC 8785)
                                                         │
                                             Ed25519 Signed Output Record
                                                         │
                                             5-Pillar Public Verification
```

### Complete Lifecycle Verification
```
DATASET ──► DATA HASH ──► PROVENANCE ──► MODEL VERSION ──► REVIEWER SIGNATURE
   │                                                              │
   └────────────── Append-Only Cryptographic Audit Log ───────────┘
                                  │
INFERENCE INPUT ──► PRE-INFERENCE VERIFY ──► INFERENCE OUTPUT ──► CANONICAL EVIDENCE
```

---

## 4. Technology Stack

### Backend
- **Language**: Python 3.12+
- **API Framework**: FastAPI (Async ASGI, OpenAPI documentation)
- **Data Layer**: SQLAlchemy 2.0 (Async Engine), Alembic migrations, PostgreSQL 15 / SQLite (StaticPool)
- **Validation**: Pydantic v2
- **Computer Vision**: OpenCV (headless), Pillow (dual-decode validation)
- **Cryptography & Security**: Passlib with Argon2id, PyJWT, PyNaCl / Cryptography (Ed25519)
- **Test Suite**: Pytest, Pytest-Asyncio, HTTPX

### Frontend
- **Framework**: React 19, Vite 5
- **Styling**: Tailwind CSS 3 (Cyber-defense dark theme)
- **Routing**: React Router v6
- **HTTP Client**: Axios with JWT interceptors
- **Visuals**: SVG Circular Assurance Gauges, HTML5 Canvas bounding-box rendering

---

## 5. Security Model

### Authentication
- **Argon2id** password hashing with OWASP-recommended parameters (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`).
- Strict password policy: minimum 8 characters, uppercase, lowercase, numeric, and special character requirements.
- Sliding-window rate limiting on sensitive authentication endpoints.
- Timing-safe authentication preventing username enumeration.
- Short-lived JWT access tokens (60 minutes) with real-time `is_active` database revocation checks.

### 5-Role Role-Based Access Control (RBAC)
1. `ADMIN`: Full platform configuration, user role management, system audit log verification.
2. `DATA_CONTRIBUTOR`: Creation of datasets, uploading images, freezing version trees.
3. `MODEL_CONTRIBUTOR`: Registering models, uploading weights, triggering security scans.
4. `REVIEWER`: Independent model inspection, Ed25519 digital signature approval, audit verification.
5. `INFERENCE_USER`: Detection queries, evidence record retrieval, 5-pillar verification.

*Separation of Duties*: Model contributors cannot approve their own models. Public registration strictly defaults to `INFERENCE_USER`.

### Cryptographic Assurance
- **Streaming SHA-256**: Constant $O(1)$ memory usage (64 KB chunks) for dataset and model uploads.
- **Deterministic Version Composite Trees**: `SHA256(sorted(file_hashes))` guarantees that any file addition, removal, or alteration mutates the version root digest.
- **Ed25519 Digital Signatures**: Reviewer model approvals and inference evidence records are signed with high-speed asymmetric elliptic curves.
- **Canonical Evidence Determinism**: Structured RFC 8785-compliant JSON serialization with sorted keys and normalized precision ensures deterministic hashing (`SHA256(canonical_evidence)`).
- **Append-Only Tamper-Evident Audit Chain**: Every audit event links to its predecessor via `previous_event_hash`, anchored to `GENESIS_BLOCK_HASH_VISIONTRUST_ROOT`.

### Static Model Security Scanner
- Statically inspects model binaries without execution or unsafe deserialization.
- Detects dangerous Pickle protocol opcodes: `GLOBAL` (`c`), `REDUCE` (`R`), `BUILD` (`b`), and `STACK_GLOBAL` (`\x93`).
- Intercepts dangerous OS imports and shell invocations: `os.system`, `subprocess.Popen`, `posix.system`, `builtins.eval`, `builtins.exec`, `socket.socket`.
- Blocks unverified models from automated approval.

---

## 6. Threat Model

See [docs/threat-model.md](docs/threat-model.md) for full attack surface analysis.

| Threat Scenario | Adversary Action | VisionTrust Defense | System Indicator |
| :--- | :--- | :--- | :--- |
| **Dataset Tampering** | Modifying image pixels on disk post-upload | Streaming SHA-256 + version tree recheck | `DATA INTEGRITY FAILURE` |
| **Model Replacement** | Swapping approved weights file on disk | Pre-inference hash lockdown + signature check | `MODEL INTEGRITY FAILURE` / `INFERENCE BLOCKED` |
| **Evidence Forgery** | Altering predictions in the database | Canonical JSON hashing + Ed25519 verification | `INFERENCE EVIDENCE INVALID` |
| **Audit Rewriting** | Deleting or modifying historical audit logs | Linear chain traversal from Genesis root | `AUDIT CHAIN INVALID` |
| **Privilege Escalation** | Self-assigning `ADMIN` role at registration | Strict Pydantic defaults & dependency guards | `HTTP 403 Forbidden` |

---

## 7. Installation & Setup

### Prerequisites
- **Python**: 3.12 or higher
- **Node.js**: 20 or higher (with npm)
- **Database**: PostgreSQL 15+ (or Docker, or standalone SQLite)

### 1. Clone the Repository
```powershell
git clone <repo-url>
cd "New project"
```

### 2. Configure Environment Variables
```powershell
Copy-Item .env.example backend\.env
```

Review and adjust `backend\.env` settings as needed:
```ini
ENVIRONMENT=development
DATABASE_URL=postgresql+asyncpg://visiontrust:visiontrust_secret@localhost:5432/visiontrust
DATABASE_SYNC_URL=postgresql+psycopg2://visiontrust:visiontrust_secret@localhost:5432/visiontrust
JWT_SECRET_KEY=change_this_to_a_secure_random_hex_string
FIRST_ADMIN_USERNAME=admin
FIRST_ADMIN_EMAIL=admin@visiontrust.local
FIRST_ADMIN_PASSWORD=DemoAdmin2026!
```

> **Standalone SQLite Option**: For offline local evaluation without Docker/PostgreSQL, set:
> `DATABASE_URL=sqlite+aiosqlite:///./visiontrust.db`

---

## 8. Database Setup & Demo Seeding

### Option A: Using Docker (Recommended for PostgreSQL)
```powershell
# Start PostgreSQL container
docker compose up db -d

# Run database migrations
cd backend
.\.venv\Scripts\Activate.ps1
alembic upgrade head
```

### Option B: Turnkey Demo Seeder
VisionTrust includes a seeder that creates all 5 RBAC demo accounts, the Genesis audit block, an initial verified dataset, and an approved model:

```powershell
cd backend
.\.venv\Scripts\python.exe -m scripts.seed_demo
```

**Seeded Demo Credentials:**
| Role | Username | Password | Purpose |
| :--- | :--- | :--- | :--- |
| `ADMIN` | `admin` | `DemoAdmin2026!` | Full administrative console, user role management |
| `DATA_CONTRIBUTOR` | `alice_data` | `DemoUser2026!` | Dataset creation, file upload, version freezing |
| `MODEL_CONTRIBUTOR` | `bob_models` | `DemoUser2026!` | Model registration, weights upload, scanner triggers |
| `REVIEWER` | `carol_review` | `DemoUser2026!` | Model inspection, Ed25519 signing, audit verification |
| `INFERENCE_USER` | `dave_infer` | `DemoUser2026!` | Running CV inference, inspecting 5-pillar evidence |

---

## 9. Running Locally

### Start Backend API
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
- API Endpoint: `http://localhost:8000`
- Interactive OpenAPI Docs: `http://localhost:8000/docs` (Development mode only)

### Start Frontend Application
```powershell
cd frontend
npm install
npm run dev
```
- Web Application: `http://localhost:5173`

---

## 10. Automated Testing

VisionTrust includes a test suite with **96 passing automated tests (100% pass rate)**. Tests run against an isolated in-memory SQLite database (`StaticPool`), requiring zero external dependencies:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest tests/ -v
```

### Test Suite Breakdown:
| Test Module | Tests | Verified Capability |
| :--- | :---: | :--- |
| `test_phase0_phase1.py` | 19 | Health endpoints, Argon2id, JWT, RBAC guards, rate limiting |
| `test_auth.py` | 6 | Profile retrieval, permission escalation barriers |
| `test_dataset_integrity.py` | 8 | Streaming SHA-256, path traversal sanitization, version trees |
| `test_audit_chain.py` | 6 | Genesis root anchor, sequence ordering, tamper detection |
| `test_model_registry.py` | 7 | Static opcode scanner, dangerous imports, reviewer Ed25519 signing |
| `test_cv_inference.py` | 5 | Image decoding, contour detection, terminology compliance |
| `test_inference_verification.py` | 5 | 5-pillar verification, disk tamper checks, signature validation |
| `test_trust_dashboard.py` | 3 | Real-time 100-point scoring, component breakdowns, disclaimers |
| `test_attack_demonstration.py` | 6 | Controlled attack simulator (dataset, model, output, audit) |
| `test_security_hardening.py` | 14 | Privilege escalation, IDOR, SQLi, XSS, Zip Slip, RCE interception |
| **Total** | **96** | **All 10 Project Phases Verified (100% Pass)** |

---

## 11. End-to-End Demo Workflow

See [docs/demo.md](docs/demo.md) for the complete demonstration script.

1. **Authenticate**: Open `http://localhost:5173/login`. Use the **Hackathon Demo Quick-Fill** buttons to authenticate as `alice_data` (Data Contributor).
2. **Dataset Management**:
   - Navigate to `/datasets`.
   - Create a dataset (`urban-traffic-v2`).
   - Upload sample images. Notice real-time streaming SHA-256 hashes.
   - Click **FREEZE VERSION** (`v1.0`). Observe the composite root hash.
   - Click **VERIFY INTEGRITY** to confirm the files on disk match the cryptographic record.
3. **Model Registry & Scanning**:
   - Log in as `bob_models` (Model Contributor). Navigate to `/models`.
   - Register a model (`yolo-traffic-detector`).
   - Upload model weights. Observe the automatic static opcode scanner run without deserializing weights.
4. **Reviewer Approval**:
   - Log in as `carol_review` (Reviewer).
   - Inspect the model version and click **APPROVE MODEL**.
   - Notice the generated Ed25519 digital signature. The model is now eligible for inference.
5. **Verified Inference**:
   - Log in as `dave_infer` (Inference User). Navigate to `/inference`.
   - Select the approved model and upload a test image.
   - Click **RUN INFERENCE**. The system performs pre-flight eligibility and integrity checks, processes contours, and issues a canonical Ed25519-signed evidence record.
   - Click **Verify 🔍** to run the **5-Pillar Verification Drawer** (`input_integrity`, `model_integrity`, `provenance_valid`, `evidence_integrity`, `signature_valid`).
6. **Controlled Attack Demonstration**:
   - Navigate to `/demonstration`.
   - Run **Attack 1 (Dataset Tampering)** ➔ System displays: `DATA INTEGRITY FAILURE`.
   - Run **Attack 2 (Model Tampering)** ➔ System displays: `MODEL INTEGRITY FAILURE` and `INFERENCE BLOCKED`.
   - Run **Attack 3 (Inference Output Tampering)** ➔ System displays: `INFERENCE EVIDENCE INVALID`.
   - Run **Attack 4 (Audit Chain Tampering)** ➔ System displays: `AUDIT CHAIN INVALID`.
7. **Trust Dashboard**:
   - Navigate to `/dashboard` to observe the animated 100-point Integrity Assurance Score gauge, 6-component scoring breakdown, pipeline health cards, and active security alerts feed.

---

## 12. Known Limitations & Operational Considerations

In accordance with defensible cybersecurity engineering:

1. **Computer Vision Inference Engine**: Current inference utilizes an OpenCV visual feature and contour detection pipeline for deterministic benchmarking. Production deployment with deep neural networks (e.g. YOLOv8 PyTorch models) requires GPU hardware and containerized runtime sandboxing (e.g. gVisor).
2. **Key Storage**: Ed25519 private keys are stored in the filesystem (`.keys/`) with restricted permissions (`0o600`). In mission-critical enterprise environments, keys should reside within a Hardware Security Module (HSM) or Cloud KMS (AWS KMS, HashiCorp Vault).
3. **Database Superuser Scope**: An adversary with root database privileges can alter records. While VisionTrust's linear hash chain immediately detects such tampering, append-only immutable ledgers (e.g. Amazon QLDB, RFC 3161 TSA) should be integrated for external non-repudiation.
4. **Terminology Compliance**: VisionTrust verifies cryptographic integrity and pipeline provenance; it does not claim mathematical proof of AI model correctness or general safety.

---

## 13. Documentation Index

- [Architecture Guide](docs/architecture.md)
- [Threat Model & Attack Surface](docs/threat-model.md)
- [Security Architecture & Hardening Review](docs/SECURITY_REVIEW.md)
- [Security Implementation Guide](docs/security.md)
- [API Reference](docs/api.md)
- [Hackathon Demonstration Script](docs/demo.md)
- [RBAC Permission Matrix](docs/rbac_matrix.md)

---

## 14. License

This project is licensed under the MIT License.
