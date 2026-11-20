# ForensiX Platform: Section Index & Module Map

This document tracks all sections, module paths, routes, and implementation status across the project lifecycle.

| Section | Title | Primary Path | Primary Route(s) | Status |
|:-------:|:------|:-------------|:-----------------|:------:|
| **S0** | Foundation & Single-Host Runtime | `app/config.py`, `run.py` | `GET /` | Complete |
| **S1** | Database & UI Shell | `app/db.py`, `app/modules/dashboard/` | `GET /dashboard` | Complete |
| **S2** | Security Core & Accounts | `app/security/`, `app/modules/accounts/` | `/login`, `/logout`, `/mfa`, `/admin/users` | Complete |
| **S3** | Case Management | `app/modules/cases/` | `/cases`, `/cases/new`, `/cases/<id>` | Complete |
| **S4** | Evidence Vault | `app/modules/evidence/`, `data/vault/` | `/cases/<id>/evidence` | Complete |
| **S5** | Custody Chain & Integrity Checker | `app/modules/custody/`, `app/modules/integrity/` | `/cases/<id>/custody`, `/cases/<id>/verify` | Complete |
| **S6** | Tool Adapter Framework | `app/adapters/`, `app/modules/system/` | `/system/tools`, `/system/jobs/<id>/status` | Complete |
| **S7** | Metadata & EXIF Analysis | `app/modules/metadata/` | `/cases/<id>/evidence/<eid>/metadata` | Complete |
| **S8** | Network Analysis (tshark) | `app/modules/network/` | `/cases/<id>/evidence/<eid>/network` | Complete |
| **S9** | Log Analyser | `app/modules/logs/` | `/cases/<id>/evidence/<eid>/logs` | Complete |
| **S10** | IOC Extractor & Reputation | `app/modules/iocs/` | `/cases/<id>/iocs` | Complete |
| **S11** | Investigation Timeline | `app/modules/timeline/` | `/cases/<id>/timeline` | Complete |
| **S12** | Forensic Report & Sec 63 BSA Cert | `app/modules/reports/` | `/cases/<id>/reports`, `/verify-report` | Complete |
| **S13** | System Health, Backup & Restore | `app/modules/system/` | `/system/health`, `/system/backup` | Complete |
| **S14** | Relationship Graph (Optional) | `app/modules/graph/` | `/cases/<id>/graph` | Complete |
| **S15** | Demo Data, Tests & Demo Script | `tools/make_demo_data.py`, `tests/` | CLI & Automation | Complete |
