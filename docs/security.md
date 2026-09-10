# VisionTrust — Security Implementation & Hardening Guide

**Version:** 1.0.0  
**Phase:** 10 — Final Integration & Polish  
**Status:** Approved  

---

## 1. Cryptographic Specifications & Standards

VisionTrust relies on established cryptographic primitives:

| Mechanism | Implementation | Parameters / Standard |
| :--- | :--- | :--- |
| **Password Hashing** | Argon2id via `passlib` | OWASP 2024: $m=64\text{MB}$, $t=3$, $p=4$, salt=16B |
| **File Integrity** | Streaming SHA-256 | 64 KB memory chunk buffer, 256-bit hexadecimal digest |
| **Digital Signatures** | Ed25519 via `cryptography` | Ed25519 (RFC 8032), 256-bit key size, 64-byte signature |
| **Evidence Canonicalization** | RFC 8785 JSON Formatting | Sorted dictionary keys, compact separators `(',', ':')`, normalized 4-decimal floats |
| **Audit Ledger Anchoring** | Linked Merkle Hash Chain | SHA-256 recursive chaining with Genesis root anchor |

---

## 2. Key Management & Secrets Lifecycle

### 2.1 Ed25519 Keypair Generation
- Signing keys are automatically generated on first boot if missing:
  - Private Key: `.keys/ed25519_private.pem` (PKCS#8 PEM format, permissions `0o600` on POSIX)
  - Public Key: `.keys/ed25519_public.pem` (SubjectPublicKeyInfo format)
- **Zero-Exposure Policy**: Private keys are loaded strictly into memory and never exposed via any API response, schema model, or log statement.
- The `.gitignore` file enforces exclusion of `.keys/`, `*.pem`, and `*.key`.

### 2.2 JWT Token Architecture
- Signed using HMAC-SHA256 (`HS256`) in development; configurable for asymmetric `RS256` / `Ed25519` in production.
- Access token lifespan: 60 minutes.
- Revocation: Every request evaluates `user.is_active` against the database session; deactivated users are instantly rejected regardless of token validity.

---

## 3. Storage & Ingestion Security

### 3.1 Path Traversal Sanitization
Incoming filenames undergo sanitization before any disk interaction:
```python
# Strip directory traversal characters and isolate basename
safe_basename = Path(untrusted_filename).name
# Whitelist alphanumeric, underscore, dot, hyphen
sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "_", safe_basename)
# Assign a cryptographically random UUID safe storage key
storage_name = f"{uuid.uuid4().hex}_{sanitized}"
```

### 3.2 File Format Whitelisting & Validation
- **Datasets**: Restricted strictly to `.jpg`, `.jpeg`, `.png`, `.bmp`, `.webp`.
- **Models**: Restricted strictly to `.pt`, `.onnx`, `.bin`, `.weights`, `.safetensors`.
- **Executable Blocking**: Executable and script formats (`.exe`, `.sh`, `.py`, `.bat`, `.php`, `.js`) are rejected with HTTP 400.
- **Corrupted Image Handling**: Dual PIL (`Image.open` + `verify`) and OpenCV (`cv2.imdecode`) decoding ensures corrupted or malicious image headers are caught before pipeline processing.

---

## 4. Model Security Scanning Engine

VisionTrust treats untrusted model files as potentially hostile binaries. Arbitrary `pickle.load()` is prohibited.

### Static Opcode Inspection Rules:
```
1. PROTOCOL DETECTION: Checks for Pickle protocol headers (protocols 2 through 5).
2. OPCODES INSPECTION:
   - 'c' (\x63): GLOBAL opcode (instantiates arbitrary module functions)
   - 'R' (\x52): REDUCE opcode (executes callable with argument tuple)
   - 'b' (\x62): BUILD opcode (invokes __setstate__ or dictionary update)
   - '\x93': STACK_GLOBAL opcode (dynamic module resolution)
3. SYSTEM CALL PATTERN MATCHING:
   - os.system, posix.system, subprocess., builtins.eval, builtins.exec
   - socket.socket, urllib.request, pty.spawn, shutil.rmtree
```
Models containing high-severity findings are marked `FLAGGED`, blocking automated approval.

---

## 5. Defense-in-Depth Checklist

- [x] **OWASP Top 10 Mitigation**:
  - A01 (Broken Access Control): 5-Role RBAC enforced via FastAPI dependencies.
  - A02 (Cryptographic Failures): Argon2id passwords, streaming SHA-256, Ed25519 signatures.
  - A03 (Injection): 100% parameterized queries via SQLAlchemy 2.0 ORM.
  - A04 (Insecure Design): Zero-trust pre-flight inference verification and append-only audit logs.
  - A05 (Security Misconfiguration): CORS restricted to designated origins; debug tracebacks suppressed in production.
  - A07 (Identification and Authentication Failures): Sliding-window rate limiting and timing-safe authentication.
  - A08 (Software and Data Integrity Failures): Static opcode model scanning, composite version trees, 5-pillar verification.
- [x] **No Hardcoded Secrets**: Zero production private keys, database passwords, or secret tokens committed to source control.
- [x] **Controlled Demonstration Scope**: Attack simulations operate exclusively on isolated temporary fixtures (`demo_attack_*`).
