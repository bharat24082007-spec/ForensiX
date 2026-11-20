# ForensiX Security Core (`app/security/`)

## 1. Purpose
Implements the foundational Confidentiality and Access Control pillars of the platform. Enforces cryptographic password hashing, multi-factor authentication (TOTP), strict role-based access control with per-case membership isolation, authenticated AES-256-GCM at-rest encryption, security headers, and brute-force rate limiting.

## 2. Path
`app/security/`
- `auth.py`: Argon2id password hasher, user authentication session management, step-up verification.
- `rbac.py`: Role enforcement (`Admin`, `Lead`, `Analyst`, `Reviewer`) and `@require_case_membership` decorator.
- `mfa.py`: Offline RFC 6238 TOTP engine, secret generation, and QR code rendering.
- `crypto.py`: AES-256-GCM authenticated chunked vault file encryption and decryption engine.
- `headers.py`: Strict HTTP security response headers and Content Security Policy (CSP).
- `limits.py`: In-memory rate limiting policies for authentication routes.

## 3. URL Routes
Decorates and protects routes across all application modules (`/login`, `/cases/...`, `/system/...`).

## 4. DB Tables
- `users`: Stores user identity, Argon2id password hash, TOTP secret, role, and lock status.
- `case_members`: Bridges cases to assigned users for strict data separation.

## 5. CIA Controls
- **Confidentiality**: Strong Argon2id password hashing with random salts; TOTP MFA; AES-256-GCM vault encryption at rest with master key isolated outside the vault folder (`data/keys/master.key`); Admin role separation (Admins cannot read case data without case membership); strict Content Security Policy forbidding runtime CDN links or inline script injections.
- **Integrity**: Authenticated AES-GCM tags guarantee that any ciphertext modification at rest is detected prior to decryption.
- **Availability**: Rate limiting on login routes mitigates resource exhaustion and denial-of-service attempts.

## 6. How to Test
```bash
pytest tests/test_s2_security.py
```
