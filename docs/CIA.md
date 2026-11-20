# ForensiX CIA Charter Matrix

This matrix maps every requirement from the CIA Charter to its implementing files, safeguards, and verification tests.

| Pillar | Requirement | Implementation Target | Verification Test | Status |
|:---|:---|:---|:---|:---:|
| **Confidentiality** | Single-host loopback binding (refuse 0.0.0.0 / non-loopback without ALLOW_LAN=true) | `app/config.py`, `run.py` | `tests/test_s0_runtime.py` | Verified (S0) |
| **Confidentiality** | Rejection of insecure default SECRET_KEY in production | `app/config.py` | `tests/test_s0_runtime.py` | Verified (S0) |
| **Confidentiality** | Sanitized rotating logs (no evidence, passwords, keys) | `app/logger.py` | `tests/test_s0_runtime.py` | Verified (S0) |
| **Confidentiality** | Strong password hashing (Argon2id), MFA (TOTP), session security, CSRF protection, security headers + strict CSP, rate-limited login | `app/security/auth.py`, `app/security/headers.py` | `tests/test_s2_security.py` | Verified (S2) |
| **Confidentiality** | Role-based access plus per-case membership (Admin cannot access case content without membership) | `app/security/rbac.py` | `tests/test_s2_security.py` | Verified (S2) |
| **Confidentiality** | Evidence encrypted at rest (AES-256-GCM, chunked), random UUID filenames, master key outside vault | `app/security/crypto.py`, `app/modules/evidence/service.py` | `tests/test_s4_evidence.py` | Verified (S4) |
| **Confidentiality** | Decrypted working copies live only in `data/work/`, permission-restricted and wiped after use | `app/adapters/base.py`, `app/modules/evidence/service.py` | `tests/test_s4_evidence.py` | Verified (S4, S6) |
| **Confidentiality** | Upload validation (size, extension vs magic number), path-traversal prevention, defanged IOCs | `app/modules/evidence/service.py`, `app/modules/iocs/service.py` | `tests/test_s4_evidence.py`, `tests/test_s10_iocs.py` | Verified (S4, S10) |
| **Confidentiality** | Link-free offline GPS coordinate display with zero outbound tile queries | `app/modules/metadata/service.py`, `app/templates/metadata/detail.html` | `tests/test_s7_metadata.py` | Verified (S7) |
| **Confidentiality** | Zero outbound network or DNS resolution during PCAP dissection; strict local execution | `app/modules/network/service.py` | `tests/test_s8_network.py` | Verified (S8) |
| **Integrity** | SHA-256 of plaintext taken at intake, stored, re-verified on access, export, and schedule | `app/modules/evidence/service.py`, `app/modules/integrity/service.py` | `tests/test_s4_evidence.py`, `tests/test_s5_custody.py` | Verified (S4, S5) |
| **Integrity** | Hash-chained, insert-only custody log (DB triggers block UPDATE and DELETE; verify function checks links) | `app/schema.sql`, `app/modules/custody/service.py` | `tests/test_s1_schema.py`, `tests/test_s5_custody.py` | Verified (S1, S5) |
| **Integrity** | Analysis on working copies with SHA-256 checked before and after tool execution | `app/adapters/base.py` | `tests/test_s6_adapters.py` | Verified (S6) |
| **Integrity** | Tool execution logging (tool name, version, arguments, input hash in custody chain) | `app/adapters/base.py` | `tests/test_s6_adapters.py` | Verified (S6) |
| **Integrity** | Metadata timestamp UTC normalization into timeline events and hidden anomaly detection (EOF overlay, entropy) | `app/modules/metadata/service.py` | `tests/test_s7_metadata.py` | Verified (S7) |
| **Integrity** | Network flow event extraction, IOC generation, and automated heuristic rules (PORT_SCAN, DNS_SPIKE) | `app/modules/network/service.py` | `tests/test_s8_network.py` | Verified (S8) |
| **Integrity** | Verbatim raw log line retention, exact 1-based line indexing, UTC timestamp normalization, and threat rules (SUCCESS_AFTER_FAILURES, BRUTE_FORCE) | `app/modules/logs/service.py` | `tests/test_s9_logs.py` | Verified (S9) |
| **Integrity** | Multi-source unified investigation timeline with UTC sorting, severity propagation, and custody-logged CSV export | `app/modules/timeline/service.py`, `app/modules/timeline/routes.py` | `tests/test_s11_timeline.py` | Verified (S11) |
| **Integrity** | Entity-relationship graph modeling with NetworkX, malicious node highlighting, and offline canvas rendering | `app/modules/graph/service.py`, `app/modules/graph/routes.py` | `tests/test_s14_graph.py` | Verified (S14) |
| **Integrity** | Digital report signatures (Ed25519) and Section 63 BSA certificate; Legal Hold protects records | `app/modules/reports/service.py`, `app/modules/cases/service.py` | `tests/test_s3_cases.py`, `tests/test_s12_reports.py` | Verified (S3, S12) |
| **Availability** | Graceful tool degradation (missing tools never crash the app; UI flags tool unavailable) | `app/adapters/registry.py` | `tests/test_s6_adapters.py` | Verified (S6) |
| **Availability** | Native in-memory fallback PCAP reader ensures packet dissection even when TShark/Wireshark is absent | `app/modules/network/service.py` | `tests/test_s8_network.py` | Verified (S8) |
| **Availability** | Subprocess timeouts, output caps, and upload limits | `app/adapters/base.py`, `app/config.py` | `tests/test_s6_adapters.py` | Verified (S6) |
| **Availability** | Background jobs with thread pool and status tracking (queued, running, done, failed) | `app/adapters/base.py` | `tests/test_s6_adapters.py` | Verified (S6) |
| **Availability** | Encrypted backup, verified restore, and system health status monitor | `app/modules/system/service.py` | `tests/test_s13_system.py` | Verified (S13) |
| **Availability** | Rotating structured logs; SQLite WAL mode; single watchdog instance guarded by lock | `app/logger.py`, `app/db.py`, `app/modules/integrity/watchdog.py` | `tests/test_s0_runtime.py`, `tests/test_s1_schema.py`, `tests/test_s5_custody.py` | Verified (S0, S1, S5) |
| **Integrity** | Deterministic synthetic evidence generation (EICAR, JPEG EXIF/GPS, MZ headers, synthetic PCAP) | `tools/make_demo_data.py` | `tests/test_s15_demo.py` | Verified (S15) |
| **Availability** | Sandboxed disk image analysis (The Sleuth Kit fls) with process containment & timeout | `app/adapters/sleuthkit.py` | `tests/test_s15_demo.py` | Verified (S15) |
| **Integrity** | Comprehensive 7-stage end-to-end investigation, custody audit, and tamper rejection | `docs/DEMO_SCRIPT.md`, `tests/` | `tests/test_s15_demo.py` | Verified (S15) |

---

### Cryptographic Assurance & Tail-Truncation Limitation Note
A cryptographic hash chain provides mathematical proof that no historical entry has been modified, reordered, or inserted. In ForensiX, each custody log entry stores both an entry SHA-256 hash and an **HMAC-SHA256 signature** keyed by a subkey derived from the platform master key via HKDF (`b"forensix-custody-hmac"`).
- **Adversary with Database-Only Access**: An adversary who compromises or modifies the SQL database file cannot forge or recompute a valid custody hash chain, because every link is authenticated by HMAC-SHA256 using the master key stored outside the database.
- **Limitation**: Someone who holds both database access *and* the master encryption key could recompute HMACs; therefore, the master key is strictly restricted at the OS level and exportable only via passphrase encryption.
- **Tail-Truncation Defense**: To prove that recent records have not been truncated, ForensiX anchors the head hash externally in two places:
1. **Section S12**: Every digitally signed forensic report embeds the exact `chain_head_hash` at issuance time.
2. **Section S13**: Every encrypted backup manifest preserves the cryptographic `head_hash` of the chain.

