# Accounts & Security Module (`app/modules/accounts`)

## Purpose
Provides user authentication, Argon2id password hashing, TOTP multi-factor authentication, account lockout protection, and administrative user account management.

## Path
`app/modules/accounts/`

## URL Routes
- `GET /login`, `POST /login` — User authentication with rate limiting and lockout checks.
- `GET /mfa`, `POST /mfa` — Two-factor authentication code challenge.
- `GET /logout`, `POST /logout` — Session termination and revocation.
- `GET /account` — Authenticated user profile and key management.
- `POST /account/mfa/setup` — Offline TOTP enrollment and base64 QR code generation.
- `POST /account/mfa/confirm` — TOTP confirmation and recovery backup code generation.
- `GET /admin/users` — Administrative user list (Admin role only).
- `POST /admin/users/create` — Provision new user (Admin role only).
- `POST /admin/users/<id>/toggle` — Activate or deactivate user (Admin role only).
- `POST /admin/users/<id>/reset-password` — Password reset (Admin role only).
- `POST /admin/users/<id>/change-role` — Role modification (Admin role only).

## Database Tables
- `users` (CRUD: id, name, username, role, password_hash, mfa_secret_enc, mfa_enabled, sign_pub_key, sign_priv_key_enc, is_active, failed_attempts, locked_until)

## CIA Controls Implemented
- **Confidentiality:**
  - Argon2id password hashing (time_cost=3, memory_cost=64MB, parallelism=4).
  - Password complexity policy: Minimum 12 characters, requiring digits and alphabetic characters.
  - Account lockout after 5 consecutive failures for 15 minutes.
  - Mandatory TOTP MFA for Admin and Lead roles.
  - TOTP Base32 secrets encrypted at rest with AES-256-GCM.
  - Zero outbound requests: QR codes generated offline using local base64 SVG rendering.
  - Passwords are never displayed, returned in API queries, or logged.
  - Session security: HttpOnly, SameSite=Strict, session regenerated upon login.
  - Role-based access control with `@role_required` and `@case_member_required`.
- **Availability:**
  - Login rate limiting (10 attempts / minute) to prevent brute-force attacks.

## How to Test
```bash
python -m pytest tests/test_s2_security.py -v
```
