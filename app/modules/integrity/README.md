# Evidence Integrity & Watchdog Module (`app/modules/integrity`)

## Purpose
Provides continuous, scheduled, and on-demand cryptographic verification of stored evidence files. Compares SHA-256 fingerprints of decrypted evidence streams against initial intake records to detect bit-rot, storage tampering, or decryption corruption. Automatically flags tampered items as `COMPROMISED` and records audit alerts.

## Path
`app/modules/integrity`

## URL Routes
Triggered via:
- `POST /cases/<id>/verify`: Re-verifies all physical vault files for a given case.
- `POST /system/watchdog/run`: Triggers immediate background verification sweep across all active cases.

## DB Tables
- `evidence`: Reads `stored_name`, `sha256`; updates `integrity_status` to `'COMPROMISED'` or updates `last_verified_at`.
- `custody_log`: Logs `VERIFY_FAIL` (on mismatch or decryption error) or `VERIFY_OK` events.

## CIA Controls Implemented
- **Integrity**:
  - Re-computes streaming SHA-256 over decrypted evidence chunks.
  - Validates GCM authentication tags during decryption.
  - Automatically transitions `integrity_status` to `'COMPROMISED'` upon hash mismatch or missing file.
  - Logs `VERIFY_FAIL` to custody chain with expected and computed hashes.
- **Availability**:
  - Background scheduler (`APScheduler`) runs in-process with a non-blocking mutex lock (`_WATCHDOG_LOCK`).
  - Catches exceptions per item so a corrupted file does not interrupt the sweep or crash the platform.
  - Background execution telemetry exposes state, last run timestamp, and counts.
- **Confidentiality**:
  - Decrypted streams are processed in memory and never written to unencrypted disks.

## How to Test
```bash
pytest tests/test_s5_custody.py -v
```
