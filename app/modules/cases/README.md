# Case Management Module (`app/modules/cases`)

## Purpose
Manages forensic investigations as first-class case containers. Handles automated case numbering (`CASE-YYYY-XXXX`), access membership (separation of duties), status lifecycles, and Legal Hold tamper-prevention controls.

## Path
`app/modules/cases/`

## URL Routes
- `GET /cases` — List cases accessible to the authenticated user with filtering by status and priority.
- `GET /cases/new`, `POST /cases/new` — Create a new investigation case (Lead role only).
- `GET /cases/<id>` — Case overview with case header, tabs, summary metrics, and member roster.
- `POST /cases/<id>/status` — Advance or close case status (Closing requires Lead; blocked under Legal Hold).
- `POST /cases/<id>/legal-hold` — Toggle Legal Hold flag (Lead role only).
- `POST /cases/<id>/members/add` — Assign investigator to case (Lead role only).
- `POST /cases/<id>/members/remove` — Remove investigator from case (Lead role only).

## Database Tables
- `cases` (CRUD: id, case_no, title, description, status, priority, lead_user_id, legal_hold, created_at, closed_at)
- `case_members` (CRUD: case_id, user_id)
- `users` (Read: user identities and roles)
- `custody_log` (Insert: case creation, member modification, status transition, and legal hold changes)

## CIA Controls Implemented
- **Confidentiality:**
  - Strict per-case membership: Users (including Admins) only see cases to which they are assigned.
  - Access to unassigned cases yields `404 Not Found` (never 403) to prevent case number enumeration.
- **Integrity:**
  - **Legal Hold**: While active, blocks evidence withdrawal, closing the case, and deleting reports.
  - Every case modification (creation, status update, member assignment, legal hold toggle) is logged in `custody_log`.
- **Availability:**
  - Fast indexed queries on `cases(status)`, `cases(lead_user_id)`, and `case_members(user_id)`.

## How to Test
```bash
python -m pytest tests/test_s3_cases.py -v
```
