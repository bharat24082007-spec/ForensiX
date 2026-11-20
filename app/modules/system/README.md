# System Diagnostics, Health, Backup & Recovery Module (`app/modules/system`)

## Purpose
Provides system diagnostics, external forensic executable inventory, tool availability monitoring, asynchronous job tracking, real-time health checks (DB integrity check, storage quota alerts, vault file synchronicity), encrypted full-system backups, pre-flight verified restorations, and portable case export packages for judicial and external forensics review.

## Path
`app/modules/system`

## URL Routes
- `GET /system/tools`: System forensic tool inventory, paths, version status, and execution audit history (Admin, Lead).
- `GET /system/jobs/<id>/status`: Asynchronous job status polling endpoint (JSON) (Case members).
- `GET /system/health`: Administrator deep health dashboard: SQLite `PRAGMA integrity_check`, disk quotas, vault synchronicity (Admin only).
- `GET /system/backup`: Administrator backup console: trigger AES-256-GCM backup, view existing archives (Admin only).
- `POST /system/backup`: Create encrypted full-system backup (Admin only).
- `GET /system/backups/<filename>/download`: Download encrypted backup archive (Admin only).
- `POST /system/restore`: Restore platform data and vault files with pre-flight hash/chain verification; requires typed confirmation `CONFIRM RESTORE` (Admin only).
- `GET /cases/<id>/export`: Export portable self-contained ZIP package of a case for external forensic/court review (Lead, Admin).

## DB Tables
- `tool_runs`: Tracks tool execution lifecycle (`id`, `case_id`, `evidence_id`, `tool`, `version`, `args_json`, `input_sha256`, `status`, `started_at`, `finished_at`, `error`).
- `custody_log`: Records `ANALYSIS_RUN`, `BACKUP_CREATED`, `SYSTEM_RESTORE`, and `CASE_EXPORT` audit entries.
- `cases`, `evidence`, `events`, `findings`, `iocs`: Restored or packaged during backup/export.

## CIA Controls Implemented
- **Availability**:
  - Encrypted full-system backup bundles live database snapshot (via `sqlite3.backup()`), all encrypted vault evidence, and SHA-256 manifests.
  - Safe restoration engine verifies AES-GCM ciphertext, validates file manifest hashes, and tests database integrity before overwriting live records.
  - Health page alerts when free disk storage drops below 1.0 GB to prevent database corruption.
  - Probes tool paths at startup; missing tools gracefully disable only their specific feature without crashing the server.
- **Integrity**:
  - Manifest embeds cryptographic SHA-256 hashes of every file and latest custody chain head hashes.
  - Pre-flight checks on restored database ensure chain integrity and PRAGMA integrity check pass.
  - Backup, restore, and case export operations log immutable entries to the system-level custody chain.
- **Confidentiality**:
  - Full backup archives are encrypted at rest with AES-256-GCM using the master key.
  - Restore operations require Admin role and strict typed confirmation (`CONFIRM RESTORE`).
  - Ephemeral decrypted copies in `data/work/<job_id>/` are zero-wiped and unlinked in a `finally` block.

## How to Test
```powershell
python -m pytest tests/test_s6_adapters.py tests/test_s13_system.py -v
```
