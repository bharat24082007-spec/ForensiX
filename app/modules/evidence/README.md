# Evidence Vault Module (`app/modules/evidence`)

## Purpose
Manages digital evidence intake, plaintext SHA-256 fingerprinting, chunked AES-256-GCM encryption at rest, path-traversal prevention, extension vs magic number discrepancy detection, pre-access cryptographic re-verification, and Legal-Hold-protected withdrawal.

## Path
`app/modules/evidence/`

## URL Routes
- `GET /cases/<id>/evidence` — Case evidence list with search and filtering by tag, status, and name.
- `GET /cases/<id>/evidence/upload` — File upload page with dropzone (Lead & Analyst roles).
- `POST /cases/<id>/evidence/upload` — Intake pipeline execution (streaming intake, SHA-256 calculation, AES-256-GCM vault encryption, working file wipe).
- `GET /cases/<id>/evidence/<eid>` — Evidence detail view (metadata, hash chip, audit log, tags/notes form).
- `POST /cases/<id>/evidence/<eid>/edit` — Metadata (tags and notes) update.
- `GET /cases/<id>/evidence/<eid>/download` — Download decrypted file after mandatory SHA-256 integrity verification.
- `GET /cases/<id>/evidence/<eid>/view` — In-browser preview of decrypted evidence after integrity check.
- `POST /cases/<id>/evidence/<eid>/withdraw` — Mark evidence withdrawn with formal reason (Lead role only; blocked under Legal Hold).

## Database Tables
- `evidence` (CRUD: id, case_id, display_name, stored_name, size, mime_real, sha256, integrity_status, source_type, tags, notes, withdrawn, withdrawn_reason, uploaded_by, uploaded_at, last_verified_at)
- `custody_log` (Insert: UPLOAD, VIEW, DOWNLOAD, METADATA_UPDATE, WITHDRAW, VERIFY_FAIL)

## CIA Controls Implemented
- **Confidentiality:**
  - Files encrypted at rest in 1 MiB chunks using AES-256-GCM (`data/vault/<uuid>.enc`).
  - Master key stored strictly outside the vault (`data/keys/master.key`) with restricted permissions (0600).
  - Randomized UUID file naming prevents identifier leakage.
  - Path traversal neutralization: Sanitizes uploaded filenames to strip directory traversals (`../`, `..\\`).
  - Decrypted working copies wiped with zero-byte overwrite before file deletion.
- **Integrity:**
  - SHA-256 intake fingerprinting: Plaintext hash computed while streaming upload.
  - Magic number discrepancy check: Detects files with fake extensions (e.g. `photo.jpg` containing an `MZ` executable) and marks them `SUSPICIOUS`.
  - Vault files marked read-only at OS level.
  - Access-time integrity verification: Download or view is only served if re-computed SHA-256 matches intake hash.
  - Legal Hold protection: Evidence cannot be withdrawn while Legal Hold is active. Evidence is never deleted.
- **Availability:**
  - Streaming upload and chunked AES-GCM encryption prevent memory exhaustion on large files.

## How to Test
```bash
python -m pytest tests/test_s4_evidence.py -v
```
