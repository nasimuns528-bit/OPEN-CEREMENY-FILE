# VISIONTRUST — API Specification (Phase 0 & Phase 1)

Base URL: `http://localhost:8000` or `/api`

All responses are formatted in JSON.

---

## 1. System Endpoints

### GET `/api/health`
Checks API health status and service identity.

- **Request Headers**: None
- **Response 200 OK**:
```json
{
  "status": "ok",
  "service": "VisionTrust API"
}
```

---

## 2. Authentication Endpoints

### POST `/api/auth/register`
Creates a new contributor, reviewer, or inference user account.

- **Request Body**:
```json
{
  "username": "alice_sec",
  "email": "alice@defense.org",
  "password": "SecurePassword123!",
  "role": "DATA_CONTRIBUTOR"
}
```
*Note: Allowed registration roles are `DATA_CONTRIBUTOR`, `MODEL_CONTRIBUTOR`, `REVIEWER`, `INFERENCE_USER`. `ADMIN` self-assignment is prohibited.*

- **Response 201 Created**:
```json
{
  "id": "c1a2b3c4-...",
  "username": "alice_sec",
  "email": "alice@defense.org",
  "role": "DATA_CONTRIBUTOR",
  "is_active": true,
  "created_at": "2026-09-10T21:45:00Z",
  "message": "User registered successfully"
}
```

- **Response 409 Conflict**:
```json
{
  "detail": "Username or email is already registered"
}
```

- **Response 422 Unprocessable Entity**:
Validation failure (weak password, invalid email format, forbidden admin role).

---

### POST `/api/auth/login`
Authenticates a user using credentials, returning JWT tokens. Protected by sliding-window rate limiting.

- **Request Body**:
```json
{
  "username": "alice_sec",
  "password": "SecurePassword123!"
}
```

- **Response 200 OK**:
```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "token_type": "bearer",
  "expires_in": 900
}
```

- **Response 401 Unauthorized**:
```json
{
  "detail": "Invalid username or password"
}
```

- **Response 429 Too Many Requests**:
```json
{
  "detail": "Too many login attempts. Please try again in 60 seconds."
}
```

---

### GET `/api/auth/me`
Retrieves profile and role for the currently authenticated user.

- **Headers**: `Authorization: Bearer <access_token>`
- **Response 200 OK**:
```json
{
  "id": "c1a2b3c4-...",
  "username": "alice_sec",
  "email": "alice@defense.org",
  "role": "DATA_CONTRIBUTOR",
  "is_active": true,
  "created_at": "2026-09-10T21:45:00Z",
  "last_login_at": "2026-09-10T21:45:10Z"
}
```

- **Response 401 Unauthorized**: Missing, expired, or invalid token.

---

### POST `/api/auth/logout`
Terminates the active session and logs an immutable audit event.

- **Headers**: `Authorization: Bearer <access_token>`
- **Response 200 OK**:
```json
{
  "message": "Successfully logged out"
}
```

---

### POST `/api/auth/refresh`
Rotates the refresh token for a fresh access and refresh token pair.

- **Request Body**:
```json
{
  "refresh_token": "eyJhbGciOi..."
}
```

- **Response 200 OK**:
```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "token_type": "bearer",
  "expires_in": 900
}
```
