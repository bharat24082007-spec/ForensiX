# Forensic Report Generator Module (Section S12)

## Purpose
Generates court-oriented, digitally signed PDF forensic reports via ReportLab. Includes a cover page, executive case summary, complete evidence inventory with SHA-256 digests and integrity statuses, full append-only chain-of-custody audit trail, chronological event timeline, rule findings with line references, extracted IOCs with verdicts, tool execution audit, legal basis (IT Act 2000), Section 63 Certificate (Bharatiya Sakshya Adhiniyam, 2023), and an ISO/IEC 27037 handling compliance checklist. Reports are signed with Ed25519 digital signatures with step-up password re-authentication.

## Path
`app/modules/reports/`

## URL Routes
- `GET /cases/<int:case_id>/reports` — List generated reports with status (Draft/Signed), SHA-256, and signer details.
- `POST /cases/<int:case_id>/reports/generate` — Generate comprehensive forensic PDF report (Lead, Analyst).
- `POST /cases/<int:case_id>/reports/<int:rid>/sign` — Cryptographically sign PDF with Lead's Ed25519 key (Lead only; requires password re-entry).
- `GET /reports/<int:rid>/download` — Download report PDF (Case members only; logged in custody chain).
- `GET /verify-report` & `POST /verify-report` — Cryptographically verify uploaded PDF authenticity against stored hash and Ed25519 signature.

## DB Tables Touched
- `reports` — `id`, `case_id`, `file_name`, `sha256`, `signature`, `signed_by`, `chain_head_hash`, `created_at`
- `users` — `sign_pub_key`, `sign_priv_key_enc`, `password_hash`
- `custody_log` — Appends `REPORT_GENERATED`, `REPORT_SIGNED`, `REPORT_DOWNLOAD`
- `cases`, `evidence`, `events`, `findings`, `iocs`, `tool_runs` — Queried to compile report

## CIA Controls Implemented
- **Integrity**:
  - Full custody chain verification before generation; broken chain or compromised evidence raises prominent warning banners in the PDF.
  - PDF hash signed with Ed25519 (64-byte detached signature); single-byte alteration renders verification "Modified".
  - Auto-generated Section 63 BSA certificate with embedded chain head hash and case hash references.
  - Append-only custody log records report creation, signing, and download events.
- **Confidentiality**:
  - Step-up authentication requires Lead password verification before accessing the encrypted Ed25519 private key.
  - Per-case membership checks prevent unauthorized report access or downloads (returns 404).

## How to Test
```powershell
python -m pytest tests/test_s12_reports.py -v
```
