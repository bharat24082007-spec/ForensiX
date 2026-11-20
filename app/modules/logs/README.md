# Log Analyser Module (`app/modules/logs`)

## Purpose
Transforms dense, voluminous server log captures (Linux SSH `auth.log`, Apache/Nginx web access logs) into a structured list of actionable forensic threat findings. Preserves verbatim raw lines and exact 1-based line numbers, synchronizing timeline events (`events`), suspicious host indicators (`iocs`), and security findings (`findings`).

Adheres to non-judgmental forensic reporting standards ("suspicious, needs review") with explicit investigative caveats noting that IP addresses represent network leads, not confirmed physical identities.

## Path
`app/modules/logs`

## URL Routes
- `GET /cases/<case_id>/evidence/<evidence_id>/logs`: View log findings, parameters, extracted IOCs, and raw line explorer.
- `POST /cases/<case_id>/evidence/<evidence_id>/logs/analyze`: Run rule-based correlation engine with user-selected format, year, and timezone offset.
- `GET /cases/<case_id>/evidence/<evidence_id>/logs/lines`: Fetch verbatim raw lines by exact 1-based line numbers via AJAX.
- `GET /cases/<case_id>/evidence/<evidence_id>/logs/export.json`: Export structured findings and IOCs as JSON.
- `GET /cases/<case_id>/evidence/<evidence_id>/logs/export.csv`: Export normalized events table entries as CSV.

## DB Tables
- `evidence`: Reads encrypted log archive from vault; verifies plaintext SHA-256 before analysis.
- `events`: Inserts normalized log records with `line_no`, `timestamp_utc`, `source_type` (`auth.log` or `web.log`), `src_ip`, `username`, `action`, and verbatim `raw_line`.
- `findings`: Records heuristic threat detections:
  - `SUCCESS_AFTER_FAILURES` (Severity: Critical): Authentication failures followed by successful SSH login from the same host.
  - `BRUTE_FORCE` (Severity: High): $\ge 10$ authentication failures from a single host in a 5-minute sliding window.
  - `PASSWORD_SPRAYING` (Severity: High): Single host attempting credentials against $\ge 5$ distinct accounts.
  - `ODD_HOUR_LOGIN` (Severity: Medium): Successful authentication during off-hours (00:00 to 05:00 UTC).
  - `WEB_ATTACK_SIGNATURE` (Severity: High): SQL injection (`UNION SELECT`, `' OR 1=1`), XSS (`<script>`), or path traversal (`../../etc/passwd`).
  - `SCANNER_USER_AGENT` (Severity: Medium): Automated reconnaissance tools (`sqlmap`, `nikto`, `nmap`, `gobuster`, etc.).
- `iocs`: Logs flagged source IPs (`type='ipv4'`, `verdict='Suspicious'`, `source='log_analyser'`).

## CIA Controls Implemented
- **Integrity**:
  - Source log line content is never altered or truncated in `raw_line`.
  - Exact 1-based `line_no` ensures forensic traceability to the physical log file.
  - Timestamps are strictly normalized to ISO-8601 UTC with user-supplied year and timezone assumptions stored.
  - Plaintext SHA-256 checked against vault intake fingerprint prior to decryption.
- **Confidentiality**:
  - Entire analysis pipeline runs locally in-process without outbound queries or external cloud parser calls.
  - Case membership required (`@case_member_required`); reviewer role restricted from triggering active analysis.
- **Availability**:
  - Memory-safe stream processing parses large log files line by line without crashing.
  - Timeline insertions are capped for UI performance.

## How to Test
```bash
pytest tests/test_s9_logs.py -v
```
