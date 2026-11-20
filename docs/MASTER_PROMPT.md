# MASTER PROMPT: Digital Forensic Investigation & Evidence Management Platform

Paste this whole file into Antigravity as the first message (or save it in the workspace as `docs/MASTER_PROMPT.md` and tell the agent to read it first).

---

## 0. HOW YOU (THE AGENT) MUST WORK

You are building a university-level but professionally engineered web platform. Follow these rules for the entire project.

1. **Build one section at a time**, in order (S0, S1, S2 ...). Each section in this file is small and self-contained.
2. **Before each section:** print a 5-line plan (files you will create, tables touched, routes added).
3. **After each section:** run its tests, then print a checklist titled `SECTION Sx COMPLETE` containing: the exact file paths created or changed, how to run it, how to verify it manually, and which CIA controls it implements. Then **STOP and wait for me to say "next"**.
4. **Every module folder gets a short `README.md`** stating: purpose, path, URL routes, DB tables, CIA controls, how to test. This is how a reader finds their way around the project.
5. **Use only the libraries in Section 3.** If you need another one, ask me first.
6. **Hard bans:** no `shell=True`, no CDN links at runtime (vendor every JS/CSS/font file locally), no outbound network calls except the opt-in lookups in S10, no secrets in code, no evidence content in logs, no `eval`/`exec`, no raw SQL string concatenation (use `?` parameters).
7. Write clean, typed, commented Python (PEP 8). Small functions. Business logic goes in `service.py`, HTTP handling goes in `routes.py`. Never mix them.
8. If something in this file is ambiguous, pick the simplest option, state your assumption in one line, and continue.

---

## 1. PROJECT BRIEF

**Problem statement:** Investigating cybersecurity incidents requires collecting and analysing digital evidence from multiple sources. Build a platform that **organizes digital evidence, maintains investigation timelines, and generates structured forensic reports.**

**One-line pitch:** Most systems ask you to trust their records. This platform lets anyone *verify* them: integrity is checkable, and court paperwork for Indian law is generated automatically.

### 1.1 Single-host constraint (non-negotiable)

The whole system runs on **one machine, as one process**, started with `python run.py`.

- Server: **Waitress**, a single process, bound to **`127.0.0.1:5000` only** (configurable port, never `0.0.0.0` unless `ALLOW_LAN=true`).
- Database: **SQLite** (one file, WAL mode, `busy_timeout=5000`, `foreign_keys=ON`).
- Background work: **in-process** thread pool plus APScheduler. **No Redis, Celery, Docker, Postgres or message broker.**
- Storage: local folders under `data/`.
- External tools (tshark, exiftool, etc.) are executed as local subprocesses.
- The app must run fully **offline**. Internet-based lookups are off by default.
- Cross-platform (Windows and Linux): use `pathlib` everywhere, and make external tool paths configurable in `.env`.

### 1.2 Scope: the 11 features and where they live

| # | Feature | Status | Section |
|---|---|---|---|
| 1 | Digital evidence management | Mandatory | S4 |
| 2 | Evidence integrity checker (SHA-256) | Mandatory | S5 |
| 3 | Investigation timeline | Mandatory | S11 |
| 4 | Forensic report generator | Mandatory | S12 |
| 5 | Case management | Mandatory | S3 |
| 6 | Metadata and EXIF | Mandatory | S7 |
| 7 | IOC extractor (+ optional reputation lookup) | Optional | S10 |
| 8 | Log analyser | Optional | S9 |
| 9 | AI extras | **Out of scope** (future scope) | - |
| 10 | Relationship graph | Optional, last | S14 |
| 11 | SHA-256 per document | Mandatory | S4 + S5 |

Extra tool adapters: **Wireshark (tshark)** in S8 and **ExifTool** in S7 are in scope. The Sleuth Kit is optional (S15). FTK, EnCase, AXIOM and Cellebrite are **not integrated**; only their exports (CSV, hash reports, E01) are accepted as evidence files.

---

## 2. CIA CHARTER (every section must honour this)

| Pillar | Requirement | Implemented in |
|---|---|---|
| **Confidentiality** | Strong password hashing (Argon2id), MFA (TOTP), session security, CSRF protection, security headers + strict CSP, rate-limited login | S2 |
| | Role-based access **plus per-case membership**: a user sees a case only if assigned; Admin manages users but cannot read case content unless a member (separation of duties) | S2, S3 |
| | Evidence **encrypted at rest** (AES-256-GCM, chunked), random UUID filenames, master key kept outside the vault folder | S4 |
| | Decrypted working copies live only in `data/work/`, are permission-restricted and wiped after use | S4, S6 |
| | Localhost-only binding, no CDN, no outbound calls by default, hash-only lookups when enabled | S0, S10 |
| | Upload validation (size, extension vs magic number), path-traversal-proof storage, IOC values shown defanged | S4, S10 |
| **Integrity** | SHA-256 of plaintext taken at intake, stored, re-verified on access, export and on a schedule | S4, S5 |
| | **Hash-chained, insert-only custody log** (DB triggers block UPDATE and DELETE); Verify button shows green or red with the broken entry number | S5 |
| | Originals are never modified; analysis runs on working copies with hashes checked before and after | S4, S6 |
| | Every tool run records tool name, version, arguments and input hash in the chain | S6 |
| | Reports are digitally signed (Ed25519) and verifiable; Legal Hold blocks changes | S3, S12 |
| **Availability** | Tools missing or failing degrade gracefully and never crash the app | S6 |
| | Timeouts, output caps and upload limits on every external tool and parser | S6, S4 |
| | Background jobs with visible status (queued, running, done, failed) | S6 |
| | Encrypted backup and verified restore; health page (disk space, DB, tools, last watchdog run) | S13 |
| | Rotating structured logs; SQLite WAL; single watchdog instance guarded by a lock | S0, S5 |

---

## 3. APPROVED STACK

| Purpose | Library / tool |
|---|---|
| Web framework | Flask, Flask-Login, Flask-WTF (CSRF), Jinja2 |
| Server | waitress |
| Database | stdlib `sqlite3` with a small repository layer and `schema.sql` (do not use an ORM, because triggers must be explicit) |
| Passwords / MFA | `argon2-cffi`, `pyotp`, `qrcode` |
| Crypto and hashing | `cryptography` (AESGCM, Ed25519), `hashlib` |
| Scheduler | APScheduler (in-process) |
| Metadata | `Pillow`, `pypdf` (use this instead of the deprecated PyPDF2), `python-docx`, `pefile`, `python-magic` (`python-magic-bin` on Windows) |
| Reports | ReportLab |
| Logs (optional) | `python-evtx` only if Windows logs are added |
| Graph (optional) | `networkx` (data) plus vendored vis-network (drawing) |
| Frontend | Server-rendered Jinja2 plus vanilla JS. Vendored locally: vis-timeline (timeline). No React, no jQuery. |
| Rate limiting | Flask-Limiter (memory storage is fine for a single host) |
| Testing | pytest |
| External CLI tools | `tshark`, `capinfos`, `exiftool` (paths in `.env`) |

---

## 4. PROJECT STRUCTURE (the map every section refers to)

```
forensic-platform/
├── run.py                         # S0  entry point (waitress, 127.0.0.1)
├── requirements.txt               # S0
├── .env.example                   # S0  all settings, documented
├── README.md                      # S0  install, run, demo
├── docs/
│   ├── CIA.md                     # CIA matrix with file references (fill in progressively)
│   ├── SECTIONS.md                # index of all sections and their paths
│   └── DEMO_SCRIPT.md             # S15
├── app/
│   ├── __init__.py                # S0  app factory
│   ├── config.py                  # S0
│   ├── db.py                      # S1  connection, helpers, init
│   ├── schema.sql                 # S1  tables + triggers
│   ├── security/                  # S2  Confidentiality
│   │   ├── auth.py  rbac.py  mfa.py  crypto.py  headers.py  limits.py
│   ├── modules/
│   │   ├── dashboard/             # S1  landing page
│   │   ├── accounts/              # S2  login, MFA, user admin
│   │   ├── cases/                 # S3  /cases
│   │   ├── evidence/              # S4  /cases/<id>/evidence
│   │   ├── custody/               # S5  /cases/<id>/custody
│   │   ├── integrity/             # S5  verify + watchdog
│   │   ├── metadata/              # S7
│   │   ├── network/               # S8  pcap analysis
│   │   ├── logs/                  # S9
│   │   ├── iocs/                  # S10
│   │   ├── timeline/              # S11
│   │   ├── reports/               # S12
│   │   ├── system/                # S13 backup, restore, health
│   │   └── graph/                 # S14 optional
│   │   (each module: __init__.py  routes.py  service.py  README.md)
│   ├── adapters/                  # S6 external tools, one file per tool
│   │   ├── base.py  registry.py  tshark.py  exiftool.py  sleuthkit.py(optional)
│   ├── templates/
│   │   ├── base.html  partials/  macros/        # S1 shared layout + components
│   │   └── <module>/                            # one folder per module
│   └── static/
│       ├── css/  (tokens.css, base.css, components.css)
│       ├── js/
│       ├── img/  (inline SVG icon sprite)
│       └── vendor/                              # locally vendored libs only
├── data/                          # git-ignored, created at first run
│   ├── db/  vault/  work/  reports/  backups/  keys/  logs/
├── tools/
│   └── make_demo_data.py          # S15
└── tests/                         # one test file per section: test_s4_evidence.py ...
```

---

## 5. ROLES AND PERMISSIONS (used by S2, S3 and every route)

| Action | Admin | Lead | Analyst | Reviewer |
|---|:-:|:-:|:-:|:-:|
| Manage users, system settings, backups | Yes | - | - | - |
| Create case, assign members, set status, Legal Hold | - | Yes | - | - |
| Upload evidence, run analyses | - | Yes | Yes | - |
| View evidence, timeline, findings (assigned cases only) | - | Yes | Yes | Yes |
| Draft report | - | Yes | Yes | - |
| Sign report | - | Yes | - | - |
| Withdraw evidence (reason required, blocked under Legal Hold; evidence is **never deleted**) | - | Yes | - | - |

Admin has **no** access to case content unless also made a member (separation of duties). Every permission check happens server-side on every route through a decorator, never only in the UI.

---

## 6. UI DESIGN SYSTEM (applies from S1 onward)

Goal: look like a professional security or case-management product, not a student demo.

- **Layout:** fixed left sidebar (logo, Dashboard, Cases, Reports, System) + top bar (breadcrumbs, case switcher, user menu). Inside a case, show a **case header** (case ID, title, status chip, lead) and **tabs**: Overview, Evidence, Custody, Timeline, Analysis, IOCs, Reports. Tabs and breadcrumbs make the path obvious.
- **Style:** calm, neutral palette (slate/navy with one accent), generous spacing, 8px grid, 8px radius, subtle shadows. Light theme by default plus a dark-theme toggle through CSS variables in `tokens.css`. System font stack only.
- **Status language (consistent everywhere):** green = Verified/Intact, amber = Suspicious/Needs review, red = Compromised/Broken, grey = Unknown/Pending, blue = In progress.
- **Components (build once in `templates/macros/`, reuse everywhere):** page header, card, data table (sortable, filter box, pagination, empty state), status chip, **hash display** (monospace, truncated, copy button, full value on hover), stat tile, tabs, breadcrumb, form field with inline validation, toast, confirm modal (required for destructive actions), file dropzone with progress, job-status badge, skeleton loader, key-value detail list.
- **Icons:** one inline SVG sprite in `static/img/`.
- **Accessibility:** visible focus states, labels on all inputs, AA contrast, full keyboard navigation.
- **Responsive:** desktop-first, usable down to tablet width.
- Every page has: a clear title, a one-line description of what the page is for, and a helpful empty state.

---

# SECTIONS

Each section lists its **Path**, **Goal**, **Build**, **Rules**, and **Done when**. Build in order.

---

## S0. Foundation and single-host runtime  `[Availability, Confidentiality]`

**Path:** repo root, `app/__init__.py`, `app/config.py`, `run.py`, `.env.example`, `requirements.txt`, `docs/`

**Goal:** a running, empty, secure-by-default Flask app on one host.

**Build**
- App factory, config loaded from `.env` (SECRET_KEY, DATA_DIR, HOST=127.0.0.1, PORT, MAX_UPLOAD_MB=200, TSHARK_PATH, CAPINFOS_PATH, EXIFTOOL_PATH, EXTERNAL_LOOKUPS=false, PUBLIC_VERIFY=false, WATCHDOG_INTERVAL_MIN=60).
- `run.py`: creates the `data/` subfolders (with restricted permissions where the OS supports it), initialises the DB, starts Waitress with **one process** on `127.0.0.1`.
- Rotating file logger in `data/logs/` (JSON lines). **Never log evidence content, passwords or keys.**
- `docs/SECTIONS.md` and `docs/CIA.md` skeletons.

**Rules:** refuse to start with the default SECRET_KEY, refuse non-loopback binding unless `ALLOW_LAN=true`.

**Done when:** `python run.py` serves a "Platform running" page on `http://127.0.0.1:5000`, and a unit test proves the app refuses a non-loopback host.

---

## S1. Database and UI shell  `[Integrity, Availability]`

**Path:** `app/db.py`, `app/schema.sql`, `app/modules/dashboard/`, `app/templates/base.html`, `app/templates/macros/`, `app/templates/partials/`, `app/static/css|js|img/`

**Goal:** the full schema, and the reusable professional UI shell that every later section uses.

**Build**
- `schema.sql` with these tables (add indexes and foreign keys):
  - `users(id, name, username, role, password_hash, mfa_secret_enc, mfa_enabled, sign_pub_key, sign_priv_key_enc, is_active, failed_attempts, locked_until, created_at)`
  - `cases(id, case_no, title, description, status, priority, lead_user_id, legal_hold, created_at, closed_at)`
  - `case_members(case_id, user_id)`
  - `evidence(id, case_id, display_name, stored_name, size, mime_real, sha256, integrity_status, source_type, tags, notes, withdrawn, withdrawn_reason, uploaded_by, uploaded_at, last_verified_at)`
  - `custody_log(id, case_id NULL, evidence_id NULL, user_id, action, detail_json, timestamp_utc, prev_hash, entry_hash)`: `case_id NULL` means the system chain.
  - `events(id, case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, dst_ip, username, action, raw_line)`
  - `findings(id, case_id, evidence_id, rule, severity, src_ip, count, first_seen, last_seen, evidence_lines, status)`
  - `iocs(id, case_id, type, value, first_evidence_id, verdict, source)`
  - `reputation_cache(indicator, type, verdict, detections, source, checked_at)`
  - `tool_runs(id, case_id, evidence_id, tool, version, args_json, input_sha256, status, started_at, finished_at, error)`
  - `reports(id, case_id, file_name, sha256, signature, signed_by, chain_head_hash, created_at)`
- **Triggers:** `BEFORE UPDATE` and `BEFORE DELETE` on `custody_log` must `RAISE(ABORT, 'custody_log is append-only')`.
- `db.py`: connection per request, WAL, busy timeout, parameterised helpers, `init_db()`.
- The whole **UI shell** from Section 6: `base.html`, sidebar, top bar, breadcrumbs, the macros library, CSS tokens and components, and a real **Dashboard** page (stat tiles: open cases, evidence items, integrity status, recent custody activity, all empty-state safe).

**Done when:** an UPDATE or DELETE on `custody_log` fails in a test, and the dashboard renders in light and dark themes with the shared components.

---

## S2. Security core and accounts  `[Confidentiality]`

**Path:** `app/security/`, `app/modules/accounts/`, `app/templates/accounts/`; routes `/login`, `/logout`, `/mfa`, `/account`, `/admin/users`

**Goal:** nobody reaches anything without authenticating, and nobody reaches more than their role and case membership allow.

**Build**
- Argon2id password hashing, password policy (12+ characters), account lockout after 5 failures for 15 minutes, login rate limit.
- TOTP MFA enrolment (QR code plus backup codes) and verification. MFA is mandatory for Admin and Lead.
- Session cookies: HttpOnly, SameSite=Strict, idle timeout 30 minutes, session regenerated at login.
- CSRF protection on every POST. Security headers on every response: strict CSP (self only), X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy no-referrer, no-store on authenticated pages.
- `rbac.py` decorators: `@login_required`, `@role_required(...)`, `@case_member_required` (returns 404, not 403, for cases the user cannot see).
- `crypto.py`: master key loading or creation (`data/keys/master.key`, permission 0600, **never inside `data/vault/`**) and AES-256-GCM helpers (the chunked streaming helpers are finished in S4). It also holds Ed25519 key-pair helpers.
- Admin user-management UI: create, deactivate, reset password, assign role. Passwords never displayed.
- Login, logout, failed login, lockout and role changes all write **system-chain** custody entries (the writer function arrives in S5; until then log them to the app log and wire them up in S5).
- First-run flow: create the initial Admin from the console (`python run.py --create-admin`), no default credentials.

**Done when:** tests prove unauthenticated access is redirected, a Reviewer cannot hit an upload route (403), a non-member gets 404 on a case, lockout works, and CSRF-less POSTs are rejected.

---

## S3. Case management  `[Confidentiality, Integrity]`

**Path:** `app/modules/cases/`, `app/templates/cases/`; routes `/cases`, `/cases/new`, `/cases/<id>`

**Goal:** every investigation is a case, and everything else hangs off it. (Feature 5)

**Build**
- Case list (filters: status, priority, my cases; search by number or title), create case (auto number `CASE-2026-0001`), case overview page with the case header and tabs from Section 6.
- Members: Lead assigns and removes members. Status flow: Open, In Progress, Under Review, Closed. Closing requires a Lead and writes a custody entry.
- **Legal Hold** toggle (Lead only): while on, block evidence withdrawal, status change to Closed, and report deletion; show a visible banner.
- Overview tab: summary cards (evidence count, last integrity check, open findings), recent activity.

**Done when:** a Lead can create and assign a case, an Analyst sees only assigned cases, and Legal Hold blocks the actions above (tested).

---

## S4. Evidence vault  `[Confidentiality, Integrity]`

**Path:** `app/modules/evidence/`, `app/templates/evidence/`, `data/vault/`; routes `/cases/<id>/evidence`, `/cases/<id>/evidence/upload`, `/cases/<id>/evidence/<eid>`

**Goal:** accept files safely, fingerprint them, store them encrypted and read-only. (Features 1, 11)

**Build**
- Upload with dropzone and progress. Limits: `MAX_UPLOAD_MB`, allowed extensions list in config. Real type detected with `python-magic`; **flag a mismatch** between extension and real type (for example `photo.jpg` that is really an `MZ` executable) as Suspicious.
- Intake pipeline (single function, fully tested):
  1. Stream the upload to `data/work/` while computing **SHA-256 of the plaintext**.
  2. Encrypt in chunks (AES-256-GCM, 1 MiB chunks, a unique nonce per chunk, chunk index as AAD) into `data/vault/<uuid>.enc`.
  3. Set the file read-only at OS level, insert the `evidence` row (`sha256`, `integrity_status=VERIFIED`).
  4. Write the custody entry `UPLOAD` (S5 writer; use a thin interface until S5 exists).
  5. Wipe the working file.
- Evidence list (table with the **hash display component**, integrity chip, type, size, tags, uploader), detail page (metadata, hash, status, tags, notes, custody mini-timeline), tag and note editing (changes are logged), search by name, tag or hash.
- Download or view is allowed only after an integrity check passes; the decrypted stream is served in memory or from `data/work/` and wiped afterwards. Each access writes a `VIEW` or `DOWNLOAD` custody entry.
- **Withdraw** (Lead, reason required, blocked under Legal Hold). Evidence is never deleted.
- Filenames: the display name is stored for humans, but the on-disk name is a UUID. Sanitise display names and prevent path traversal in every file operation.

**Done when:** uploading a file shows its SHA-256 in the UI, the vault file is unreadable without the key (test: raw bytes do not contain the plaintext), a traversal filename is neutralised, and a type-mismatch file is flagged.

---

## S5. Custody chain and integrity checker  `[Integrity]`

**Path:** `app/modules/custody/`, `app/modules/integrity/`, `app/templates/custody/`, `app/templates/integrity/`; routes `/cases/<id>/custody`, `/cases/<id>/verify`, `/system/chain`

**Goal:** make the project forensic. This is the headline feature. (Features 2, 11)

**Build**
- `custody/service.py::append(case_id, evidence_id, user_id, action, detail)`: the **only** function allowed to insert into `custody_log`. It runs inside one transaction and takes the latest entry hash of that chain (`case_id`, or the system chain when `NULL`) as `prev_hash` (`"0"*64` for the first entry). The entry hash is
  `SHA256(canonical_json(case_id, evidence_id, user_id, action, detail, timestamp_utc) + prev_hash)`.
  Serialise writers with a lock so a chain can never fork.
- `verify_chain(case_id)`: walk the chain from the first entry, recompute each hash and check each `prev_hash` link. Return `OK` or `BROKEN at entry N (reason)`.
- **Custody tab:** a chronological table (who, what, when, hash chip), filters by action, user and evidence, plus a prominent **Verify Chain** button. It shows green "Chain intact, N entries" or red "Broken at entry N".
- **Evidence re-verification** (`verify_evidence(eid)`): stream-decrypt, hash, compare with the stored SHA-256. A match updates `last_verified_at` and logs `VERIFY_OK`. A mismatch sets `integrity_status=COMPROMISED`, logs `VERIFY_FAIL`, and raises a red alert on the dashboard and the case.
- **Integrity watchdog:** an APScheduler job (interval from `.env`, `max_instances=1`, `coalesce=True`) that re-verifies every non-withdrawn evidence file in chunks. It must never crash the app: catch errors per item and log them. Provide a "Run now" button for Lead and Admin.
- Wire **S2's system-chain events** (login, lockout, role changes) into `append`.
- Honest limitation (state it in `docs/CIA.md`): deleting the *last* entries of a chain cannot be detected by the chain alone. Mitigate by storing `chain_head_hash` in every signed report (S12) and in every backup manifest (S13).

**Done when (all automated):** (a) 5 appended entries verify OK; (b) editing one row directly in SQLite is blocked by the trigger; (c) after bypassing the trigger in a test (drop it, edit, restore) `verify_chain` reports the right entry number; (d) modifying a vault file's bytes makes the watchdog mark that evidence COMPROMISED.

---

## S6. Tool adapter framework  `[Availability, Integrity, Confidentiality]`

**Path:** `app/adapters/` (`base.py`, `registry.py`), `app/modules/system/` (tool status), job-status UI in `templates/macros/`

**Goal:** one safe, uniform way to run any external tool or parser, so the analysis sections stay small.

**Build**
- `base.py::run_tool(tool_key, args: list[str], input_evidence_id, timeout, max_output_bytes)`:
  - args as a **list** (never `shell=True`), executable path from config, never from user input
  - decrypt the evidence into a private working folder `data/work/<job_id>/`, hash it **before and after** the run (must match)
  - capture stdout with a hard size cap, enforce the timeout, kill the process on overrun
  - capture the tool **version** (for example `tshark --version`) once and cache it
  - insert a `tool_runs` row and a custody entry (`ANALYSIS_RUN`: tool, version, args, input hash)
  - wipe the working folder in a `finally` block
  - return a structured result or a clean error; never raise to the user
- `registry.py`: at startup run `shutil.which`/path checks for each tool and store `available / missing / version`. A missing tool **disables only that feature**, with a clear message in the UI.
- Jobs: run in a small thread pool (max 2 workers). Job states: queued, running, done, failed. UI polls a status endpoint and shows a **job-status badge**; the page never freezes.
- System page "Tools" showing each tool's status, version and path.

**Done when:** a test runs a harmless command through `run_tool`, proves the timeout kills a sleeping process, proves the output cap, proves the working copy is wiped, and a missing tool yields a graceful "unavailable" result.

---

## S7. Metadata and EXIF  `[Integrity]`

**Path:** `app/modules/metadata/`, `app/adapters/exiftool.py`, `app/templates/metadata/`; route `/cases/<id>/evidence/<eid>/metadata`

**Goal:** reveal the hidden details in files. (Feature 6)

**Build**
- Primary extractor: **ExifTool** (`exiftool -json -n`, via S6). Fallback if ExifTool is missing: Pillow (images), pypdf (PDF), python-docx (Office), pefile (executables).
- Extract and store per evidence (JSON on the evidence row or a child table): image camera/model, capture time, editing software, **GPS**; PDF/Office author, organisation, created/modified, revision info; executable compile time, imports summary, packer hints.
- **Hidden-data checks:** extension vs magic mismatch (from S4), bytes appended after a JPEG end marker (`FF D9`), high entropy flag.
- Normalise every timestamp to **UTC** (keep the original string and the assumed zone) and add rows to `events` (`source_type=metadata`) so the timeline can use them.
- UI: a clean key-value metadata card grouped by category, a "suspicious findings" strip, a Leaflet-free GPS display (coordinates plus a link-free text block; an offline map is optional and out of scope).

**Done when:** a JPEG with EXIF shows its camera, time and GPS; a fake `.jpg` that is really an executable is flagged; metadata times appear in `events` in UTC.

---

## S8. Network analysis with Wireshark (tshark)  `[Integrity, Availability]`

**Path:** `app/modules/network/`, `app/adapters/tshark.py`, `app/templates/network/`; route `/cases/<id>/evidence/<eid>/network`

**Goal:** turn an uploaded `.pcap`/`.pcapng` into events, indicators and findings.

**Build**
- Adapter commands (list args, via S6): `capinfos` (packet count, start/end time, capture hash) and `tshark -r <file> -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport -e dns.qry.name -e http.host -e http.request.uri -E separator=, -E header=y` with a packet cap (default 200,000) and timeout.
- Parse the output into `events` (`source_type=pcap`, UTC), and feed IPs, DNS names, HTTP hosts and URLs to the IOC extractor (S10).
- Findings rules: **port scan** (one source hits 20 or more distinct ports within a minute), **DNS spike**, **connection to rare external IP** (simple frequency heuristic). Each finding links to packet time ranges.
- UI: capture summary card, top talkers table, DNS queries table, findings list. Show the exact command line, tool version and input hash used (repeatability).

**Rules:** never execute or "open" payload content; this module only reads tshark's text fields.

**Done when:** a sample pcap (supplied by me in `tools/demo/sample.pcap`) yields events and IOCs, and a missing tshark disables this tab with a clear message.

---

## S9. Log analyser  `[Integrity]`

**Path:** `app/modules/logs/`, `app/templates/logs/`; route `/cases/<id>/evidence/<eid>/logs`

**Goal:** turn thousands of log lines into a short list of findings, each pointing to the exact lines. (Feature 8)

**Build**
- Pipeline: parse, normalise, detect, score, report. Supported formats: **Linux SSH `auth.log`** and **Apache/Nginx access log** (list others as future scope). The user picks the format and supplies the **year and time zone assumption** (logs often lack them); store the assumption.
- Normalise into `events` (`line_no`, `timestamp_utc`, `source_type`, `src_ip`, `username`, `action`, `raw_line` kept unchanged).
- Detection rules (rules are the main method; no ML): **brute force** (10 or more failures from one IP in 5 minutes, sliding window), **success after failures (Critical)**, **password spraying**, **odd-hour login (00:00 to 05:00)**, **web attack signatures** (`' OR 1=1`, `UNION SELECT`, `<script>`, `../../etc/passwd`), **scanner user-agents** (sqlmap, nikto, nmap, masscan).
- Findings table with severity chips, source IP, count, time range and a **view lines** link showing the original raw lines. Findings add attacker IPs to the IOC table and rows to the timeline.
- Language: say "suspicious, needs review", never "guilty". Add a note that IPs are leads, not identities.

**Done when:** the demo `auth.log` (150 failures then a success) produces a Critical "success after failures" finding that points to the right line numbers.

---

## S10. IOC extractor and reputation (optional, offline-first)  `[Confidentiality]`

**Path:** `app/modules/iocs/`, `app/templates/iocs/`; route `/cases/<id>/iocs`

**Goal:** collect indicators of compromise across all evidence. (Feature 7)

**Build**
- Extractor (regex plus validation: IPv4 octets 0-255, valid TLD for domains) for IPv4, domains, URLs, emails, SHA-256/MD5 hashes. Scans text, logs, pcap fields and strings of files. Deduplicate per case and record which evidence each value came from.
- **Defang on display** (`hxxp://evil[.]com`) and never render IOCs as clickable links.
- IOC table: filter by type, verdict, evidence; copy and export CSV.
- **Reputation (optional, OFF unless `EXTERNAL_LOOKUPS=true`):** lookup order = local `reputation_cache` (7-day expiry), then offline known-good hash list (NSRL subset, if the user supplies one), then MalwareBazaar, then VirusTotal. **Send only hashes, IPs and domains, never files.** Respect VirusTotal's free tier (4 requests/min, 500/day; confirm current limits before the demo), handle 404 as "Unknown", 429 as "retry later", and store the lookup date. Every outgoing lookup writes a custody entry listing exactly what left the system. Per-case "offline mode" toggle forces no lookups.
- Verdict labels: Known good, Known malicious, Suspicious, No detections (not proof of safety), Unknown. State that a reputation verdict is a **lead, not proof**.

**Done when:** IOCs from the demo log, pcap and a text file are extracted and deduplicated; with lookups disabled, no network call is ever made (tested by mocking the HTTP client and asserting zero calls).

---

## S11. Investigation timeline  `[Integrity]`

**Path:** `app/modules/timeline/`, `app/templates/timeline/`, `app/static/vendor/vis-timeline/`; route `/cases/<id>/timeline`

**Goal:** show the story of the incident in time order. (Feature 3)

**Build**
- Merge `events` from metadata, logs, pcap and custody actions into one list `(time_utc, source, event, evidence_id, severity)`.
- Interactive timeline (vis-timeline, vendored) plus a table view; filter by source, evidence, severity and date range; click an event to open its evidence or raw log lines.
- Highlight findings (Critical/High) and compromised evidence. Show a clear "all times are UTC" label and per-event original timezone info where known.
- Export timeline as CSV (export is logged in the custody chain).

**Done when:** events from at least three sources appear in one sorted, filterable view, and the CSV export matches the table.

---

## S12. Forensic report, signature and Section 63 certificate  `[Integrity]`

**Path:** `app/modules/reports/`, `app/templates/reports/`, `data/reports/`; routes `/cases/<id>/reports`, `/reports/<rid>/download`, `/verify-report`

**Goal:** generate the final court-oriented document and prove it is authentic. (Feature 4)

**Build**
- **PDF via ReportLab** with sections: cover (case number, title, investigator, date), case summary, evidence list with SHA-256 and integrity status, **chain-of-custody trail** (and chain-verification result plus `chain_head_hash`), timeline, findings (with line references), IOCs (with verdict and date checked, if lookups were used), tools and versions used, limitations, legal basis (IT Act, 2000), **Section 63 certificate (Bharatiya Sakshya Adhiniyam, 2023)** auto-filled from stored data including hash values, and an **ISO/IEC 27037 handling checklist**.
- **Before generating:** verify the custody chain and all evidence hashes. If anything is COMPROMISED or BROKEN, the report prints a prominent warning (do not silently proceed).
- **Signing:** Lead re-enters their password (step-up auth), the PDF's SHA-256 is signed with their **Ed25519** private key (stored encrypted), the signature is saved in the `reports` table and a detached `.sig`. Stamp the signer and date on the report.
- **Verify Report page:** upload a PDF, show Authentic or Modified, the signer and signing date. Accessible to logged-in users (public only if `PUBLIC_VERIFY=true`).
- The Section 63 template must say "prepared according to the prescribed format; verify the wording against the official BSA schedule before court use". Do not claim guaranteed court acceptance.
- Reports list per case (status Draft or Signed, hash, signer), download logged in custody.

**Done when:** a signed report verifies as Authentic, and changing a single byte of the PDF makes the Verify page show Modified (automated test).

---

## S13. System: backup, restore and health  `[Availability]`

**Path:** `app/modules/system/`, `app/templates/system/`, `data/backups/`; routes `/system/health`, `/system/backup`, `/system/restore`, `/system/tools`

**Goal:** the platform survives mistakes and disk problems.

**Build**
- **Health page** (Admin): DB integrity (`PRAGMA integrity_check`), free disk space with a warning threshold, vault file count vs `evidence` rows (detect missing files), last watchdog run and result, tool availability, job queue status.
- **Backup:** uses the SQLite backup API for a consistent DB copy, bundles it with the encrypted vault files and a **manifest** (file names, sizes, SHA-256, `chain_head_hash` per case) into `data/backups/backup-<timestamp>.zip`, encrypted with the master key.
- **Case export (portable package):** one case as a ZIP with its manifest of hashes for external review.
- **Restore:** verifies the manifest hashes and re-verifies every custody chain **before** replacing data; refuses on mismatch. Restore requires Admin and a typed confirmation.
- Backup, restore and export actions write system-chain custody entries.

**Done when:** a backup restores into a clean data folder, chains verify afterwards, and a tampered backup is rejected.

---

## S14. Relationship graph (optional)  `[Integrity]`

**Path:** `app/modules/graph/`, `app/templates/graph/`; route `/cases/<id>/graph`

**Build:** nodes (IPs, domains, users, evidence files) and edges (logged in from, connects to, contains, found in) from `events`, `iocs` and `findings`; `networkx` for the data, vendored vis-network for drawing; nodes with Suspicious/Malicious verdicts turn red. Filters by node type. Build only after S1-S13 are complete.

---

## S15. Tests, demo data and demo script  `[All]`

**Path:** `tests/`, `tools/make_demo_data.py`, `tools/demo/`, `docs/DEMO_SCRIPT.md`, `docs/CIA.md`

**Build**
- `make_demo_data.py` generates: a fake `auth.log` (a few normal logins, then 150 failed logins from one IP, then a success), a JPEG with EXIF and GPS (Pillow), the **EICAR** test file, a fake `photo.jpg` that is really an executable header, and a short text file with IPs and URLs. (The sample pcap is provided separately by me.)
- Complete `pytest` suite, one file per section, plus a full end-to-end test.
- Finish `docs/CIA.md`: a table mapping each CIA control to the file and test that proves it.
- Write `docs/DEMO_SCRIPT.md` (3 to 4 minutes):
  1. Log in with MFA, create a case, upload a file, and show its SHA-256.
  2. Open the custody log, and click Verify (green).
  3. Tamper with one custody row (instructions for temporarily dropping the trigger), click Verify (red, with the entry number).
  4. Modify a vault file, run the watchdog, and show COMPROMISED.
  5. Upload `auth.log`, and show the Critical finding, the timeline and the IOCs.
  6. Generate and sign the report, then verify it.
  7. Change one byte of the PDF, and show Modified.
- Optional (S-opt): The Sleuth Kit adapter (`app/adapters/sleuthkit.py`) listing files inside an uploaded disk image with `fls`, only after everything above passes.

---

## 7. DEFINITION OF DONE (whole project)

- `python run.py` is the only command needed; it listens on 127.0.0.1 only; it works offline.
- All tests pass; each section's `README.md` exists; `docs/SECTIONS.md` and `docs/CIA.md` are complete and accurate.
- Every CIA row in Section 2 points to working code and a passing test.
- The UI is consistent: the same components, status colours, breadcrumbs and tabs on every page.
- The demo script runs start to finish without manual fixes.

## 8. EXPLICITLY OUT OF SCOPE

AI features, mobile and cloud acquisition, FTK/EnCase/AXIOM/Cellebrite integration (their exports only), live packet capture, multi-host or cloud deployment, Docker, real malware samples, and any claim of guaranteed legal admissibility.

---

**START NOW with Section S0 only. Print your plan, build it, run its tests, print the completion checklist, and wait for me to say "next".**
