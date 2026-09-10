# VisionTrust — Hackathon Demonstration Guide

**Project**: VisionTrust (Computer Vision Integrity Assurance Fabric)  
**Target Audience**: Hackathon Judges, Evaluators, and Technical Reviewers  
**Estimated Time**: 5–7 minutes  

---

## 1. Quick Setup Before Demonstration

Ensure both backend and frontend servers are active:

```powershell
# Terminal 1: Backend API
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000

# Terminal 2: Frontend Web Console
cd frontend
npm run dev
```

Open browser to: `http://localhost:5173`

---

## 2. Seeded Demo Accounts Quick Reference

The platform includes five pre-seeded demo accounts representing the distinct roles in a multi-contributor AI pipeline:

| Role | Username | Password | Purpose in Demo |
| :--- | :--- | :--- | :--- |
| `DATA_CONTRIBUTOR` | `alice_data` | `DemoUser2026!` | Uploading datasets, computing SHA-256 hashes, version trees |
| `MODEL_CONTRIBUTOR` | `bob_models` | `DemoUser2026!` | Uploading weights, static bytecode scanning |
| `REVIEWER` | `carol_review` | `DemoUser2026!` | Model inspection, Ed25519 digital signature issuance |
| `INFERENCE_USER` | `dave_infer` | `DemoUser2026!` | Querying CV inference, 5-pillar evidence verification |
| `ADMIN` | `admin` | `DemoAdmin2026!` | Full access, user management, audit chain verification |

> **Pro-Tip**: Use the **Hackathon Demo Quick-Fill** buttons on the `/login` page to switch roles with a single click!

---

## 3. 15-Step Step-by-Step Demonstration Flow

### Step 1: Login as Data Contributor
- Navigate to `http://localhost:5173/login`.
- Click the **📁 Data Contrib** quick-fill button (`alice_data`).
- Click **Authenticate**.

### Step 2: Ingest New Dataset
- Click **Datasets** in the sidebar (`/datasets`).
- Click **+ NEW DATASET**.
- Enter Name: `surveillance_cam_04`, Description: `Perimeter traffic monitoring feed`.
- Click **Create Dataset**.

### Step 3: Upload Image Files & Observe Streaming SHA-256
- Select the newly created dataset in the left pane.
- Under **Upload Dataset Images**, select one or more image files (`.jpg`, `.png`).
- Watch files upload. Explain to judges:
  > *"Every image is processed in 64 KB streaming chunks. The backend computes the cryptographic SHA-256 digest on-the-fly with constant memory footprint."*

### Step 4: Freeze Version & Show Cryptographic Provenance
- In the **Freeze New Version** panel, enter Version Tag: `v1.0`.
- Click **🔒 FREEZE VERSION**.
- Point out the **Composite Dataset Root Hash**:
  > *"VisionTrust sorts all individual file hashes and computes a composite tree hash: `SHA256(sorted(file_hashes))`. Any modified, missing, or added file will permanently alter this root digest."*

### Step 5: Register Model & Run Static Security Scanner
- Log out, then log in as `bob_models` (**🤖 Model Contrib**).
- Navigate to **Model Registry** (`/models`).
- Click **+ REGISTER MODEL**.
  - Name: `perimeter_detector_yolo`, Framework: `YOLOv8`, Type: `object_detection`.
- Click **Upload New Weights Version**:
  - Version Tag: `v1.0`.
  - Select any model weights file (`.bin`, `.onnx`, `.pt`).
- Notice the **Security Scan Status: PASSED**:
  > *"Notice how the model was scanned before storage. VisionTrust uses a custom static opcode analyzer that detects dangerous Pickle opcodes (`GLOBAL`, `REDUCE`, `STACK_GLOBAL`) and shell execution imports (`os.system`, `subprocess`) without deserializing or running untrusted code."*

### Step 6: Reviewer Verification & Asymmetric Ed25519 Signing
- Log out, then log in as `carol_review` (**🛡️ Reviewer**).
- Return to **Model Registry** (`/models`) and select `perimeter_detector_yolo`.
- Notice the **APPROVE MODEL VERSION** button (only visible to Reviewers).
- Click **APPROVE MODEL**.
- Highlight the **Reviewer Ed25519 Signature**:
  > *"The reviewer has now cryptographically bound their identity to the exact SHA-256 hash of the model weights. The signature can be verified offline by any third-party auditor."*

### Step 7: Execute Verified Computer Vision Inference
- Log out, then log in as `dave_infer` (**Inference User**).
- Navigate to **Inference Pipeline** (`/inference`).
- Select the approved model `perimeter_detector_yolo (v1.0)`.
- Choose any test image (`.jpg` or `.png`).
- Click **RUN INFERENCE**.
- Point out:
  1. The canvas renders bounding boxes with confidence scores.
  2. The compliance statement: *"Model prediction — integrity verified across data, model, and execution pipeline."* (Adheres strictly to trustworthy terminology guidelines).

### Step 8: Inspect Cryptographically Verifiable Evidence (5-Pillar Drawer)
- On the live inference result or in the historical log table, click **Verify 🔍**.
- The **Cryptographic Evidence Verification Drawer** opens. Show the judges all 5 verified pillars:
  - ✅ **Input Image Integrity**: Physical image hash on disk matches stored input digest.
  - ✅ **Model Integrity**: Model weights hash on disk matches approved hash.
  - ✅ **Provenance & Authorization**: Model approved by certified Reviewer.
  - ✅ **Canonical Evidence Integrity**: Canonical RFC 8785 JSON matches output digest.
  - ✅ **Asymmetric Signature**: Ed25519 signature verified with platform public key.

---

### Step 9: Controlled Attack 1 — Dataset Tampering
- Navigate to **Attack Simulator** (`/demonstration`).
- Under **Attack 1 — Dataset Tampering**, click **SIMULATE DATASET TAMPERING**.
- Watch the live telemetry execute:
  1. Registers test dataset.
  2. Computes original SHA-256 hash.
  3. Intentionally modifies a test image on disk.
  4. Recalculates hash ➔ detects mismatch.
- Show the critical banner:
  ```text
  DATA INTEGRITY FAILURE
  ```

### Step 10: Controlled Attack 2 — Model Tampering & Inference Blocking
- Under **Attack 2 — Model Tampering & Inference Blocking**, click **SIMULATE MODEL TAMPERING**.
- Watch the live telemetry execute:
  1. Registers clean model and reviewer signature.
  2. Injects weight mutations into the weights file on disk.
  3. Pre-flight verification catches the hash discrepancy.
  4. **Blocks inference immediately**.
- Show the dual banners:
  ```text
  MODEL INTEGRITY FAILURE
  INFERENCE BLOCKED
  ```

### Step 11: Controlled Attack 3 — Inference Output Tampering
- Under **Attack 3 — Inference Output Tampering**, click **SIMULATE INFERENCE TAMPERING**.
- Telemetry shows:
  1. Executes valid inference with Ed25519 signature.
  2. Injects falsified predictions into the database record.
  3. 5-Pillar verification detects the canonical digest mismatch.
- Show the banner:
  ```text
  INFERENCE EVIDENCE INVALID
  ```

### Step 12: Controlled Attack 4 — Audit Chain Tampering
- Under **Attack 4 — Audit Chain Tampering**, click **SIMULATE AUDIT TAMPERING**.
- Telemetry shows:
  1. Modifies historical audit record in database.
  2. Chain traversal detects broken hash linkage from Genesis root.
- Show the banner:
  ```text
  AUDIT CHAIN INVALID
  ```

### Step 13: View Multi-Contributor Audit Chain
- Navigate to **Audit Chain** (`/audit`).
- Filter by action or view the latest security alerts (`DATASET_TAMPER_DETECTED`, `MODEL_TAMPER_DETECTED`).
- Click **🔒 VERIFY COMPLETE CHAIN** to verify all blocks from Genesis to HEAD.

### Step 14: Return to Trust Dashboard
- Navigate to **Dashboard** (`/dashboard`).
- Point out:
  - **Dynamic Assurance Score**: Shows score degradation if active alerts are unaddressed.
  - **Component Breakdown**: 6 operational pillars (Data, Models, Provenance, Contributors, Inference, Security Scans).
  - **Active Security Alerts**: Pinpoints recent tamper events.

### Step 15: Conclude with Operational Disclaimer
- Point to the mandatory operational disclaimer on the dashboard:
  > *"Integrity assurance metrics measure system provenance, cryptographic hash consistency, and security scanning; not mathematical proof of AI correctness."*
- Highlight that VisionTrust practices defensible, zero-trust engineering without making unrealistic claims of being "100% secure."
