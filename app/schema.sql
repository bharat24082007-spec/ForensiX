-- ==============================================================================
-- ForensiX Platform Database Schema
-- Digital Forensic Investigation & Evidence Management Platform
-- Strict foreign keys, WAL mode, parameterised queries, and append-only triggers.
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------------
-- 1. Users Table
-- Roles: Admin, Lead, Analyst, Reviewer
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('Admin', 'Lead', 'Analyst', 'Reviewer')),
    password_hash TEXT NOT NULL,
    mfa_secret_enc TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK(mfa_enabled IN (0, 1)),
    sign_pub_key TEXT,
    sign_priv_key_enc TEXT,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- ------------------------------------------------------------------------------
-- 2. Cases Table
-- Status: Open, In Progress, Under Review, Closed
-- Priority: Low, Medium, High, Critical
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_no TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'In Progress', 'Under Review', 'Closed')),
    priority TEXT NOT NULL DEFAULT 'Medium' CHECK(priority IN ('Low', 'Medium', 'High', 'Critical')),
    lead_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    legal_hold INTEGER NOT NULL DEFAULT 0 CHECK(legal_hold IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    closed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_cases_case_no ON cases(case_no);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_lead_user ON cases(lead_user_id);

-- ------------------------------------------------------------------------------
-- 3. Case Members Table (Per-Case Membership for Separation of Duties)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_members (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_case_members_user ON case_members(user_id);

-- ------------------------------------------------------------------------------
-- 4. Evidence Table
-- Integrity Status: VERIFIED, SUSPICIOUS, COMPROMISED, UNVERIFIED
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    mime_real TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    integrity_status TEXT NOT NULL DEFAULT 'VERIFIED' CHECK(integrity_status IN ('VERIFIED', 'SUSPICIOUS', 'COMPROMISED', 'UNVERIFIED')),
    source_type TEXT NOT NULL,
    tags TEXT,
    notes TEXT,
    withdrawn INTEGER NOT NULL DEFAULT 0 CHECK(withdrawn IN (0, 1)),
    withdrawn_reason TEXT,
    uploaded_by INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    last_verified_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(integrity_status);

-- ------------------------------------------------------------------------------
-- 5. Custody Log Table (Append-Only Hash-Chained Audit Trail)
-- case_id NULL denotes the system chain (login, lockout, user admin, backups).
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS custody_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE RESTRICT,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE RESTRICT,
    user_id INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    timestamp_utc TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    entry_hmac TEXT
);

CREATE INDEX IF NOT EXISTS idx_custody_case ON custody_log(case_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_log(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_timestamp ON custody_log(timestamp_utc);

-- Strict Triggers: Ensure custody_log is strictly append-only
CREATE TRIGGER IF NOT EXISTS trg_custody_log_no_update
BEFORE UPDATE ON custody_log
BEGIN
    SELECT RAISE(ABORT, 'custody_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_custody_log_no_delete
BEFORE DELETE ON custody_log
BEGIN
    SELECT RAISE(ABORT, 'custody_log is append-only');
END;

-- ------------------------------------------------------------------------------
-- 6. Events Table (Timeline Events from Logs, PCAP, Metadata, Custody)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    line_no INTEGER,
    timestamp_utc TEXT NOT NULL,
    source_type TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    username TEXT,
    action TEXT NOT NULL,
    raw_line TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_evidence ON events(evidence_id);

-- ------------------------------------------------------------------------------
-- 7. Findings Table (Automated Findings from Rules/Parsers)
-- Severity: Low, Medium, High, Critical
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    src_ip TEXT,
    count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT,
    evidence_lines TEXT,
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'Reviewed', 'Dismissed'))
);

CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- ------------------------------------------------------------------------------
-- 8. IOCs Table (Indicators of Compromise)
-- Type: ipv4, domain, url, email, hash_sha256, hash_md5
-- Verdict: Unknown, Known good, Suspicious, Known malicious, No detections
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK(type IN ('ipv4', 'domain', 'url', 'email', 'hash_sha256', 'hash_md5')),
    value TEXT NOT NULL,
    first_evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    verdict TEXT NOT NULL DEFAULT 'Unknown' CHECK(verdict IN ('Unknown', 'Known good', 'Suspicious', 'Known malicious', 'No detections')),
    source TEXT NOT NULL,
    UNIQUE (case_id, type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_case ON iocs(case_id);
CREATE INDEX IF NOT EXISTS idx_iocs_type_val ON iocs(type, value);

-- ------------------------------------------------------------------------------
-- 9. Reputation Cache Table (Offline/Local Reputation Cache)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reputation_cache (
    indicator TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    verdict TEXT NOT NULL,
    detections INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    checked_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

-- ------------------------------------------------------------------------------
-- 10. Tool Runs Table (Subprocess Audit and Repeatability)
-- Status: queued, running, done, failed
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    tool TEXT NOT NULL,
    version TEXT NOT NULL,
    args_json TEXT NOT NULL DEFAULT '[]',
    input_sha256 TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued', 'running', 'done', 'failed')),
    started_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    finished_at TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_tool_runs_case ON tool_runs(case_id);

-- ------------------------------------------------------------------------------
-- 11. Reports Table (Signed Forensic Reports)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    file_name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    signature TEXT NOT NULL,
    signed_by INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    chain_head_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE INDEX IF NOT EXISTS idx_reports_case ON reports(case_id);
