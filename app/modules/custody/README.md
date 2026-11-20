# Chain of Custody Module (`app/modules/custody`)

## Purpose
Provides an append-only, mathematically verifiable cryptographic audit ledger for all forensic actions across investigations and administrative platform lifecycle events. Every entry is sequentially linked via SHA-256 hash chaining over canonical JSON representations.

## Path
`app/modules/custody`

## URL Routes
- `GET /cases/<id>/custody`: Chronological case custody trail with real-time verification and filtering.
- `POST /cases/<id>/verify`: On-demand cryptographic chain and evidence verification.
- `GET /system/chain`: System-wide audit trail and integrity watchdog telemetry (Admin & Lead roles).
- `POST /system/chain/verify`: Verify integrity of the system event ledger.
- `POST /system/watchdog/run`: Execute an immediate background integrity sweep.

## DB Tables
- `custody_log`: Primary append-only audit trail table (`id`, `case_id`, `evidence_id`, `user_id`, `action`, `detail_json`, `timestamp_utc`, `prev_hash`, `entry_hash`).
- Protected by SQLite triggers `prevent_custody_log_update` and `prevent_custody_log_delete` which raise `ABORT`.

## CIA Controls Implemented
- **Integrity**:
  - Hash chain: `entry_hash = SHA256(canonical_json + prev_hash)`.
  - Genesis link: `GENESIS_PREV_HASH = "0" * 64`.
  - Deterministic serialization: canonical JSON with alphabetically sorted keys and compact delimiters.
  - Insert-only database triggers blocking UPDATE and DELETE.
  - Re-entrant thread locking (`_CHAIN_LOCK`) prevents concurrent chain forks.
  - Verification algorithm reports exact broken entry ID and sequence number upon tampering.
- **Confidentiality**:
  - Case membership enforcement (`case_member_required`). Non-members and unauthorized users receive 404.
  - System chain restricted to Admin and Lead roles (`@role_required("Admin", "Lead")`).
- **Availability**:
  - On-demand verification runs in-process with minimal latency.
  - Filtering by action, user, and evidence ID keeps UI responsive.

## How to Test
```bash
pytest tests/test_s5_custody.py -v
```
