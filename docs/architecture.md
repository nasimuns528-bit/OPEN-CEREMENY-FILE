# VisionTrust — System Architecture

**Version:** 1.0.0  
**Phase:** 10 — Final Integration & Polish  
**Status:** Approved  

---

## 1. High-Level Architecture Overview

VisionTrust provides an end-to-end cryptographic integrity assurance fabric for multi-contributor Computer Vision pipelines. The system operates on a zero-trust architecture: every artifact (training dataset, neural network weights file, inference query, and prediction output) is deterministically hashed, cryptographically signed, and anchored to an append-only audit ledger.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             CLIENT TIER                                     │
│  React 19 + Vite 5 + Tailwind CSS 3                                         │
│  - Cyber Security Dashboard with 100-Point Assurance Dial                  │
│  - Dataset & Model Registry Management                                      │
│  - OpenCV Bounding-Box Inference Canvas & 5-Pillar Verification Drawer      │
│  - Controlled Attack Simulator Console                                      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTPS / JSON & Multipart Forms
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API GATEWAY                                    │
│  FastAPI (Python 3.12 ASGI)                                                 │
│  - Sliding-Window Rate Limiting                                             │
│  - Argon2id Password Derivation                                             │
│  - JWT Bearer Authentication & 5-Role RBAC Authorization                   │
│  - Strict Basename Sanitization & Path Traversal Guards                     │
└───────┬──────────────┬──────────────┬──────────────┬──────────────┬─────────┘
        │              │              │              │              │
        ▼              ▼              ▼              ▼              ▼
┌──────────────┐┌──────────────┐┌──────────────┐┌──────────────┐┌─────────────┐
│   Dataset    ││    Model     ││   Inference  ││    Audit     ││  Dashboard  │
│   Registry   ││   Registry   ││    Engine    ││    Chain     ││   Scoring   │
│   Service    ││   Service    ││   Service    ││   Service    ││   Engine    │
└───────┬──────┘└──────┬───────┘└──────┬───────┘└──────┬───────┘└──────┬──────┘
        │              │               │               │               │
        │              ▼               │               │               │
        │       ┌──────────────┐       │               │               │
        │       │ Static Model │       │               │               │
        │       │ Opcode Scan  │       │               │               │
        │       └──────────────┘       │               │               │
        ▼                              ▼               ▼               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CRYPTOGRAPHIC LAYER                               │
│  - Streaming SHA-256 (64 KB Chunked Hashing)                                │
│  - Deterministic Version Composite Trees: SHA256(sorted(hashes))            │
│  - Canonical Evidence Determinism (RFC 8785)                                │
│  - Ed25519 Asymmetric Signatures (Model Approval & Inference Records)      │
│  - Chained Audit Ledger with Genesis Block Root Anchor                      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PERSISTENCE LAYER                                 │
│  - PostgreSQL 15 / SQLite (SQLAlchemy 2.0 Async ORM + Alembic Migrations)   │
│  - Isolated File Storage (UUID-Named Blobs in datasets/ models/ inference/) │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 Authentication & RBAC Core
- **Password Security**: Argon2id memory-hard hashing (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`).
- **Token Management**: HS256 JWT tokens with 60-minute lifetime. Every authenticated request validates `user.is_active` directly in the database session.
- **5-Role RBAC Matrix**:
  - `ADMIN`: Global administration, user management, audit verification.
  - `DATA_CONTRIBUTOR`: Uploading datasets, managing versions.
  - `MODEL_CONTRIBUTOR`: Registering models, uploading weights.
  - `REVIEWER`: Independent model verification, Ed25519 signing.
  - `INFERENCE_USER`: Detection queries, evidence record retrieval.

### 2.2 Dataset Integrity & Provenance Subsystem
- **Streaming Upload**: Computes SHA-256 hash incrementally in 64 KB buffers, ensuring $O(1)$ RAM usage.
- **Deterministic Composite Trees**: Dataset versions compute a root digest across all member file hashes sorted lexicographically:
  $$\text{Root Hash} = \text{SHA256}\left(\sum \text{sorted}(\text{file\_hashes})\right)$$
- **On-Demand Disk Verification**: Re-hashes actual on-disk files and compares against the database. Any discrepancy marks the dataset `TAMPERED` and logs an alert.

### 2.3 Model Registry & Security Scanning Subsystem
- **Pre-Deserialization Scanner**: Reads raw binary bytes without loading weights into PyTorch or Python runtimes.
- **Pickle Opcode Interception**: Detects `GLOBAL` (`c`), `REDUCE` (`R`), `BUILD` (`b`), and `STACK_GLOBAL` (`\x93`) opcodes.
- **System Call Detection**: Scans for `os.system`, `subprocess.Popen`, `builtins.eval`, `socket.socket`, and other RCE signatures.
- **Reviewer Signing**: Approved models are cryptographically signed using Ed25519 across canonical metadata:
  $$\text{Payload} = \text{model\_id} \parallel \text{version} \parallel \text{sha256\_hash} \parallel \text{status}$$

### 2.4 Computer Vision Inference & Evidence Verification Subsystem
- **Pre-Flight Eligibility**: Verifies model status (`APPROVED`), scan result (`PASSED`), on-disk file hash consistency, and reviewer signature validity before allowing inference.
- **Visual Detection Engine**: Dual PIL + OpenCV image decoding, visual feature and contour detection.
- **Deterministic Canonical Evidence**: Serializes evidence in sorted, whitespace-free JSON before hashing:
  $$\text{Evidence Digest} = \text{SHA256}(\text{canonical\_json}(\text{inference\_id}, \text{input\_hash}, \text{model\_hash}, \dots))$$
- **Ed25519 Evidence Signing**: The canonical evidence digest is signed using the platform's private key.
- **5-Pillar Verification Endpoint**:
  1. `input_integrity`: Recomputed image hash matches recorded input hash.
  2. `model_integrity`: Recomputed weights hash matches approved model hash.
  3. `provenance_valid`: Model was reviewer-approved with valid signature.
  4. `evidence_integrity`: Canonical evidence matches stored output hash.
  5. `signature_valid`: Ed25519 evidence signature is mathematically valid.

### 2.5 Tamper-Evident Audit Chain
- **Genesis Anchor**: Seeded with `GENESIS_BLOCK_HASH_VISIONTRUST_ROOT`.
- **Cryptographic Hash Linkage**:
  $$\text{Event Hash}_n = \text{SHA256}(\text{seq}_n \parallel \text{action}_n \parallel \text{actor}_n \parallel \text{details}_n \parallel \text{Event Hash}_{n-1})$$
- **Chain Verification**: Linear traversal from block 1 to HEAD. Any deleted, inserted, or modified event invalidates the chain and pinpoints the exact corrupted sequence number.

---

## 3. Database Schema Entity Relationship

```
┌──────────────────┐       1:N       ┌─────────────────────┐
│      users       ├────────────────►│      datasets       │
└────────┬─────────┘                 └──────────┬──────────┘
         │                                      │ 1:N
         │ 1:N                                  ▼
         │                           ┌─────────────────────┐
         │                           │   dataset_versions  │
         │                           └──────────┬──────────┘
         │                                      │ 1:N
         │                                      ▼
         │                           ┌─────────────────────┐
         │                           │    dataset_files    │
         │                           └─────────────────────┘
         │
         │ 1:N                       ┌─────────────────────┐
         ├──────────────────────────►│       models        │
         │                           └──────────┬──────────┘
         │                                      │ 1:N
         │                                      ▼
         │                           ┌─────────────────────┐       1:N       ┌──────────────────────┐
         │                           │    model_versions   ├────────────────►│ model_security_scans │
         │                           └──────────┬──────────┘                 └──────────────────────┘
         │                                      │ 1:N
         │                                      ▼
         │ 1:N                       ┌─────────────────────┐
         ├──────────────────────────►│  inference_records  │
         │                           └─────────────────────┘
         │
         │ 1:N
         └──────────────────────────►┌─────────────────────┐
                                     │    audit_events     │
                                     │ (chained to prev)   │
                                     └─────────────────────┘
```

---

## 4. Operational Telemetry & Scoring

The dashboard scoring engine evaluates platform assurance across 6 weighted components (Total 100 Points):
1. **Data Integrity (20 Points)**: Ratio of verified vs tampered dataset versions.
2. **Model Integrity (20 Points)**: Ratio of approved clean models vs rejected versions.
3. **Provenance Chain (15 Points)**: Mathematical validity of the linear audit chain.
4. **Contributor Trust (15 Points)**: Proportion of active contributors adhering to RBAC policies.
5. **Inference Evidence (15 Points)**: Proportion of verified Ed25519-signed inference records.
6. **Security Scanning (15 Points)**: Proportion of models passing static bytecode inspection.
