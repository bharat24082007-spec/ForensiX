# Core Application Package (`app/`)

## Purpose
Provides the foundational application factory, configuration parsing, directory provisioning, single-host runtime constraints, and structured JSON logging.

## Path
`app/`

## URL Routes
- `GET /` — Root verification page ("ForensiX Platform running")
- `GET /health` — Runtime health and loopback configuration status

## Database Tables
None in S0 (full schema introduced in S1).

## CIA Controls Implemented
- **Confidentiality:**
  - Loopback host enforcement: Rejects non-loopback bindings (`0.0.0.0`, LAN IPs) unless `ALLOW_LAN=true`.
  - Secret key validation: Rejects missing, short, or placeholder keys (`change-me`, `insecure-default-key`, etc.).
  - Sensitive parameter scrubber: Automatically redacts passwords, tokens, master keys, and private keys from JSON logs.
- **Availability:**
  - Single-host, in-process runtime architecture (Waitress WSGI).
  - Provisioning of isolated data folders (`data/db`, `data/vault`, `data/work`, `data/reports`, `data/backups`, `data/keys`, `data/logs`).
  - Rotating structured log files (10 MB per file, 5 backups).

## How to Test
```bash
python -m pytest tests/test_s0_runtime.py -v
```
