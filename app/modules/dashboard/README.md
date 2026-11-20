# Dashboard Module (`app/modules/dashboard`)

## Purpose
Provides the primary forensic operational dashboard, displaying real-time metrics, case statuses, vault evidence summary, cryptographic integrity posture, and recent custody log activity.

## Path
`app/modules/dashboard/`

## URL Routes
- `GET /` — Redirects to / renders the dashboard overview.
- `GET /dashboard` — Main investigation dashboard page with stat tiles, active cases, and recent custody activity.

## Database Tables
- `cases` (Read: open/total counts, recent active cases)
- `evidence` (Read: count, status breakdown: VERIFIED, SUSPICIOUS, COMPROMISED)
- `custody_log` (Read: latest 5 immutable audit entries)
- `users` (Read: investigator names linked to cases and audit actions)

## CIA Controls Implemented
- **Integrity:**
  - Evaluates overall platform integrity status from evidence records.
  - Highlights critical alerts when compromised evidence is detected.
  - Displays SHA-256 hash badges for recent custody chain entries.
- **Availability:**
  - Empty-state safe: Gracefully renders default cards and zero counts when tables contain no records.
  - Fast query aggregation using SQLite indexes.

## How to Test
```bash
python -m pytest tests/test_s1_schema.py -v
```
