# VISIONTRUST — Role-Based Access Control (RBAC) Matrix

## Roles Overview

VisionTrust enforces strict least-privilege RBAC across 5 distinct system roles:

1. **`ADMIN`**: Full platform management, user administration, security policy controls, audit chain verification.
2. **`DATA_CONTRIBUTOR`**: Uploads computer vision training/validation datasets, generates initial file hashes, registers data provenance.
3. **`MODEL_CONTRIBUTOR`**: Uploads trained CV model weights (YOLO, ONNX), attaches model metadata and training provenance.
4. **`REVIEWER`**: Security auditor and model validator; performs ModelScan inspection and grants production approval.
5. **`INFERENCE_USER`**: Submits test images to approved models, verifies Ed25519 signatures and composite trust scores.

---

## Permission Matrix

| Capability / Resource | ADMIN | DATA_CONTRIBUTOR | MODEL_CONTRIBUTOR | REVIEWER | INFERENCE_USER |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **System Health** (`/api/health`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Self Profile** (`/api/auth/me`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| **User Management** (`/api/users/*`) | ✓ | ✗ | ✗ | ✗ | ✗ |
| **Dataset Upload & Hashing** | ✓ | ✓ | ✗ | ✗ | ✗ |
| **Dataset Provenance View** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Model Upload** | ✓ | ✗ | ✓ | ✗ | ✗ |
| **Model Security Approval** | ✓ | ✗ | ✗ | ✓ | ✗ |
| **Submit Inference Request** | ✓ | ✓ | ✓ | ✗ | ✓ |
| **View Signed Evidence** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Audit Log Tamper Inspection** | ✓ | ✗ | ✗ | ✓ | ✗ |
| **Full Audit Trail View** | ✓ | ✗ | ✗ | ✓ | ✗ |
