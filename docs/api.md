# VisionTrust — Complete REST API Specification

**Base URL**: `http://localhost:8000/api`  
**OpenAPI Docs**: `http://localhost:8000/docs` (Development mode)  
**Security Scheme**: `Authorization: Bearer <JWT_ACCESS_TOKEN>`  

---

## 1. Authentication & User Management

### `POST /api/auth/register`
- **Access**: Public
- **Description**: Registers a new user account. Role is strictly assigned as `INFERENCE_USER`.
- **Request Body**:
  ```json
  {
    "username": "alice_sec",
    "email": "alice@example.com",
    "password": "StrongPassword123!"
  }
  ```
- **Responses**: `201 Created`, `400 Bad Request`, `422 Validation Error`

### `POST /api/auth/login`
- **Access**: Public (Protected by sliding-window rate limiting)
- **Description**: Authenticates user credentials via Argon2id verification and returns a JWT access token.
- **Request (OAuth2 Form)**:
  ```text
  username=alice_sec&password=StrongPassword123!
  ```
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "role": "DATA_CONTRIBUTOR"
  }
  ```

### `GET /api/auth/me`
- **Access**: Authenticated
- **Description**: Returns profile details and active permissions for the current token bearer.

### `GET /api/users`
- **Access**: `ADMIN`
- **Description**: Lists all registered users. Supports updating roles and toggling `is_active`.

---

## 2. Dataset Management & Integrity

### `POST /api/datasets`
- **Access**: `DATA_CONTRIBUTOR`, `ADMIN`
- **Description**: Creates a new dataset metadata container.
- **Request Body**:
  ```json
  {
    "name": "traffic_surveillance_v1",
    "description": "Urban highway camera footage annotations"
  }
  ```

### `GET /api/datasets`
- **Access**: Authenticated
- **Query Params**: `skip=0`, `limit=50`
- **Description**: Lists registered datasets with file counts, current status, and root hash.

### `GET /api/datasets/{dataset_id}`
- **Access**: Authenticated
- **Description**: Retrieves full dataset detail including all version snapshots and files.

### `POST /api/datasets/{dataset_id}/files`
- **Access**: `DATA_CONTRIBUTOR`, `ADMIN`
- **Request**: `multipart/form-data` with `files` (array of image files)
- **Description**: Uploads image files in streaming chunks, validates extensions, computes SHA-256 digests, and links files to the dataset.

### `POST /api/datasets/{dataset_id}/versions`
- **Access**: `DATA_CONTRIBUTOR`, `ADMIN`
- **Description**: Freezes current unversioned files into a named version and calculates the deterministic composite SHA-256 tree hash.
- **Request Body**:
  ```json
  {
    "version_tag": "v1.0"
  }
  ```

### `POST /api/datasets/{dataset_id}/verify`
- **Access**: Authenticated
- **Description**: Recalculates physical SHA-256 hashes of all files on disk and compares against stored digests. Returns `VERIFIED` or `TAMPERED`.

---

## 3. Computer Vision Model Registry

### `POST /api/models`
- **Access**: `MODEL_CONTRIBUTOR`, `ADMIN`
- **Description**: Registers a model entry in the platform.
- **Request Body**:
  ```json
  {
    "name": "yolov8n-pedestrian",
    "description": "YOLOv8 Nano model trained on urban pedestrian crossings",
    "framework": "YOLOv8",
    "model_type": "object_detection"
  }
  ```

### `GET /api/models`
- **Access**: Authenticated
- **Description**: Lists all registered models, approval states, and scan results.

### `POST /api/models/{model_id}/versions`
- **Access**: `MODEL_CONTRIBUTOR`, `ADMIN`
- **Request**: `multipart/form-data`
  - `version_tag`: `v1.0`
  - `file`: model binary (`.pt`, `.bin`, `.onnx`, `.safetensors`)
  - `associated_dataset_version`: (Optional UUID)
- **Description**: Stores model weights, computes streaming SHA-256, and executes the static bytecode scanner.

### `POST /api/models/{model_id}/versions/{version_id}/approve`
- **Access**: `REVIEWER`, `ADMIN` (Separation of duties enforced)
- **Description**: Formally approves a model version and issues an Ed25519 digital signature.
- **Response `200 OK`**:
  ```json
  {
    "model_id": "...",
    "version_tag": "v1.0",
    "approval_status": "APPROVED",
    "ed25519_signature": "6c4b2a9e...",
    "approved_by": "carol_review"
  }
  ```

### `POST /api/models/{model_id}/versions/{version_id}/verify`
- **Access**: Authenticated
- **Description**: Verifies that the model weights on disk match the approved database hash.

---

## 4. Computer Vision Inference & Verification

### `POST /api/inference/detect`
- **Access**: `INFERENCE_USER`, `REVIEWER`, `ADMIN`
- **Request**: `multipart/form-data`
  - `model_id`: UUID
  - `version_id`: (Optional UUID, defaults to latest approved)
  - `image`: image file (`.jpg`, `.jpeg`, `.png`, `.bmp`, `.webp`)
- **Workflow**:
  1. Validates model eligibility (`APPROVED`, `PASSED`, matching hash, valid signature).
  2. Decodes image safely via Pillow & OpenCV.
  3. Executes visual feature and contour detection.
  4. Generates RFC 8785 canonical evidence payload.
  5. Computes `output_hash = SHA256(canonical_evidence)`.
  6. Signs evidence with platform Ed25519 private key.
- **Response `200 OK`**:
  ```json
  {
    "inference_id": "8f3b2a1c-...",
    "input_hash": "e3b0c44298fc...",
    "model_id": "...",
    "model_version_tag": "v1.0",
    "model_hash": "4a5c6e8f...",
    "predictions": [
      {
        "class_name": "visual_contour",
        "confidence": 0.88,
        "bbox": [120, 85, 340, 290]
      }
    ],
    "highest_confidence": 0.88,
    "output_hash": "b2c3d4e5...",
    "evidence_signature": "7f8a9b...",
    "verification_status": "VERIFIED",
    "integrity_statement": "Model prediction — integrity verified across data, model, and execution pipeline."
  }
  ```

### `GET /api/inference/records`
- **Access**: Authenticated
- **Query Params**: `skip=0`, `limit=50`
- **Description**: Lists historical inference execution records.

### `POST /api/inference/{inference_id}/verify`
- **Access**: Authenticated
- **Description**: Performs independent 5-pillar verification of an inference evidence record.
- **Response `200 OK`**:
  ```json
  {
    "inference_id": "8f3b2a1c-...",
    "input_integrity": true,
    "model_integrity": true,
    "provenance_valid": true,
    "evidence_integrity": true,
    "signature_valid": true,
    "overall_status": "VERIFIED",
    "discrepancies": []
  }
  ```

---

## 5. Tamper-Evident Audit Ledger

### `GET /api/audit`
- **Access**: Authenticated
- **Query Params**: `skip=0`, `limit=50`, `action=...`, `resource_type=...`
- **Description**: Retrieves chronologically sequenced audit logs with previous and current hash linkages.

### `POST /api/audit/verify`
- **Access**: `REVIEWER`, `ADMIN`
- **Description**: Verifies the entire cryptographic hash chain from the Genesis block to HEAD.
- **Response `200 OK`**:
  ```json
  {
    "valid": true,
    "events_checked": 52,
    "first_invalid_event": null,
    "tamper_details": null,
    "chain_head_hash": "8f1a2b3c..."
  }
  ```

---

## 6. Trust Dashboard & Scoring

### `GET /api/dashboard/metrics`
- **Access**: Authenticated
- **Description**: Computes real-time 100-point Integrity Assurance Score, 6 component metrics, pipeline counts, active alerts, and mandatory operational disclaimer.

---

## 7. Controlled Attack Demonstration Simulator

### `POST /api/demonstration/attack/{attack_type}`
- **Access**: `REVIEWER`, `ADMIN`
- **Path Param**: `dataset_tampering` | `model_tampering` | `inference_tampering` | `audit_tampering`
- **Description**: Simulates safe, isolated tampering on temporary test assets (`demo_attack_*`) and returns chronological execution telemetry proving system detection.
