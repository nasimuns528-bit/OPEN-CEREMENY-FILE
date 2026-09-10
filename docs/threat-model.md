# VisionTrust — Threat Model & Attack Surface Analysis

**Version:** 1.0.0  
**Phase:** 10 — Final Integration & Polish  
**Status:** Approved  

---

## 1. Adversary Capabilities & Trust Assumptions

VisionTrust evaluates threat vectors against five distinct adversary tiers:

```
Tier 1: External Unauthenticated Threat Actor
Tier 2: Authenticated Low-Privilege User (Inference User)
Tier 3: Compromised Contributor Account (Data or Model Contributor)
Tier 4: Rogue Database or Storage Operator (Partial DB Write Access)
Tier 5: Host OS Root / Physical Memory Attacker (Residual Risk Domain)
```

### Trust Assumptions
- The Python 3.12 interpreter and operating system kernel are uncompromised during execution.
- Ed25519 private keys stored on the filesystem are protected by OS-level file permissions (`0o600`).
- TLS terminates securely between clients and the API gateway.

---

## 2. Threat Vector Analysis & Mitigation Matrix

### THREAT-01: Training Dataset Poisoning & Silent Tampering
- **Attacker Profile**: Tier 3 (Compromised Data Contributor) or Tier 4 (Storage Operator).
- **Objective**: Alter training images or label annotations post-review to inject subtle backdoors or degrade model accuracy.
- **Attack Vector**: Direct modification of image bytes on disk or replacement of dataset files after version freeze.
- **VisionTrust Mitigations**:
  1. *Streaming SHA-256*: File digests are calculated in 64 KB buffers upon upload and permanently stored in `dataset_files`.
  2. *Deterministic Version Trees*: Dataset version root hashes are derived from lexicographically sorted member file hashes. Modifying a single bit in any file mutates the composite digest.
  3. *On-Demand Integrity Auditing*: The `/api/datasets/{id}/verify` endpoint recalculates physical disk hashes against stored digests.
  4. *Audit Logging*: Controlled tampering triggers a `DATASET_TAMPER_DETECTED` audit record and sets the status to `TAMPERED`.
- **System Indicator**: `DATA INTEGRITY FAILURE`

---

### THREAT-02: Trojaned Model Weights & Deserialization RCE
- **Attacker Profile**: Tier 3 (Compromised Model Contributor) or Tier 4 (Storage Operator).
- **Objective**: Execute arbitrary shell commands on inference servers via Pickle exploits or replace approved weights with an unverified model.
- **Attack Vector**: Uploading a `.pt` / `.bin` file containing `os.system` / `subprocess.Popen` opcodes; or modifying an approved model binary on disk before execution.
- **VisionTrust Mitigations**:
  1. *Static Opcode Inspection*: `model_scanner.py` inspects raw binary bytes without loading weights. Detects Pickle protocol headers (`\x80\x02`–`\x80\x05`) and opcodes (`GLOBAL`, `REDUCE`, `BUILD`, `STACK_GLOBAL`).
  2. *Dangerous Symbol Interception*: Binary byte scanning matches prohibited calls: `os.system`, `subprocess.Popen`, `posix.system`, `builtins.eval`, `socket.socket`, `shutil.rmtree`.
  3. *Separation of Duties*: Model contributors cannot approve their own models. Only independent `REVIEWER` accounts can sign approval metadata.
  4. *Pre-Flight Eligibility Checks*: Prior to every inference request, the engine checks:
     - `model.approval_status == 'APPROVED'`
     - `model.security_scan_status == 'PASSED'`
     - Recomputed SHA-256 on disk == database `sha256_hash`
     - Ed25519 reviewer digital signature is cryptographically authentic
  5. *Immediate Block*: Any hash discrepancy immediately halts execution and logs `MODEL_TAMPER_DETECTED`.
- **System Indicators**: `MODEL INTEGRITY FAILURE` & `INFERENCE BLOCKED`

---

### THREAT-03: Inference Output Fabrication & Disputed Detections
- **Attacker Profile**: Tier 2 (Malicious Consumer) or Tier 4 (Database Manipulator).
- **Objective**: Falsify detection results, forge safety clearance certificates, or alter recorded confidence scores.
- **Attack Vector**: Direct SQL manipulation of `predictions_json` or fabrication of counterfeit inference records.
- **VisionTrust Mitigations**:
  1. *Canonical JSON Serialization (RFC 8785)*: Deterministic formatting sorts keys, normalizes floating-point precision, and eliminates extraneous whitespace.
  2. *Output Evidence Hashing*: `output_hash = SHA256(canonical_evidence_json)`.
  3. *Ed25519 Digital Signing*: The platform signs the canonical evidence using its private key, linking input image hash, model hash, and predictions into an immutable record.
  4. *5-Pillar Verification Endpoint*: The `/api/inference/{id}/verify` endpoint independently verifies image hash, model hash, reviewer approval, canonical evidence match, and signature validity.
- **System Indicator**: `INFERENCE EVIDENCE INVALID`

---

### THREAT-04: Historical Audit Log Rewriting & Anti-Forensics
- **Attacker Profile**: Tier 4 (Rogue Operator attempting to conceal malicious activity).
- **Objective**: Delete audit events, modify actor usernames, or fabricate retrospective logs.
- **Attack Vector**: Direct `UPDATE` or `DELETE` SQL queries against `audit_events`.
- **VisionTrust Mitigations**:
  1. *Append-Only Chained Ledger*: Every audit record includes `previous_event_hash`, forming a linear cryptographic hash chain.
  2. *Genesis Anchor*: Initialized from `GENESIS_BLOCK_HASH_VISIONTRUST_ROOT`.
  3. *Monotonic Sequence Ordering*: Strict sequence numbers enforce linear chronology.
  4. *Full-Chain Verification*: Traversing from block 1 to HEAD mathematically detects any insertion, deletion, or modification, reporting the exact invalid sequence number.
- **System Indicator**: `AUDIT CHAIN INVALID`

---

### THREAT-05: Privilege Escalation & Broken Object-Level Authorization (BOLA)
- **Attacker Profile**: Tier 2 (Authenticated Low-Privilege User).
- **Objective**: Approve models, access administrative logs, or mutate other contributors' assets.
- **Attack Vector**: Passing `role: ADMIN` in public registration payloads, calling reviewer endpoints, or guessing sequential resource IDs.
- **VisionTrust Mitigations**:
  1. *Self-Registration Lockdown*: Public registration strictly hardcodes `INFERENCE_USER`.
  2. *FastAPI Dependency Guards*: `require_role("ADMIN", "REVIEWER")` validates JWT role claims on every protected route.
  3. *UUIDv4 Identifiers*: All entities utilize non-sequential UUIDs to prevent enumeration.
  4. *Argon2id Key Derivation*: Memory-hard password hashing prevents offline brute-force.
- **System Indicator**: `HTTP 403 Forbidden`

---

## 3. Residual Risks & Infrastructure Mitigations

| Residual Risk | Attack Description | Recommended Production Defense |
| :--- | :--- | :--- |
| **Kernel / Root Compromise** | An attacker with host root access can modify Python runtime memory or extract private keys. | Deploy on hardened Linux instances with Secure Boot, SELinux, and EDR agents. |
| **In-Memory Model Mutation** | Weights altered in GPU VRAM after disk integrity check. | Execute inference inside hardware-isolated enclaves (AMD SEV-SNP, Intel SGX). |
| **Private Key Extraction** | Compromise of the `.keys/` directory on disk. | Migrate Ed25519 signing keys to a Hardware Security Module (HSM) or Cloud KMS. |
| **Database Superuser Write** | Direct superuser tampering of audit logs. | Anchor audit chain HEAD digests periodically to external immutable logs (RFC 3161 TSA, WORM storage). |
