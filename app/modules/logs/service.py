"""
ForensiX Log Analyser Service.
Provides ingestion, timestamp/timezone normalization, pattern extraction,
and automated threat rule detection for Linux SSH auth.log and Apache/Nginx web access logs.
Generates:
- events table entries with exact 1-based line numbers and raw verbatim lines
- findings table threat records (BRUTE_FORCE, SUCCESS_AFTER_FAILURES, etc.)
- iocs table records for suspicious/malicious IP addresses
"""

from __future__ import annotations

import io
import re
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.db import query_db, execute_db
from app.modules.evidence.service import get_evidence_details, verify_and_decrypt_evidence


# Regex Patterns for Linux SSH auth.log
RE_SYSLOG_DATE = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")
RE_ISO_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")

RE_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2",
    re.IGNORECASE,
)
RE_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2",
    re.IGNORECASE,
)
RE_SSH_INVALID_USER = re.compile(
    r"Invalid user (\S+) from (\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# Regex for Apache / Nginx Combined Access Log
# Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
RE_WEB_ACCESS = re.compile(
    r'^(\S+) \S+ (\S+) \[([\w:/]+\s[+\-]\d{4})\] "([A-Z]+)\s+([^\s"]+)(?:\s+HTTP/[\d\.]+)?(?:")\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?',
)

# Web Attack Signatures
WEB_ATTACK_PATTERNS = [
    (re.compile(r"(?:'|\%27)\s*(?:OR|AND)\s+.*(?:=|<|>|LIKE)", re.IGNORECASE), "SQL_INJECTION", "' OR 1=1 style SQLi boolean pattern"),
    (re.compile(r"UNION(?:\s+ALL)?\s+SELECT", re.IGNORECASE), "SQL_INJECTION", "UNION SELECT SQLi projection query"),
    (re.compile(r"(?:SLEEP\(\d+\)|BENCHMARK\(\d+,)", re.IGNORECASE), "SQL_INJECTION", "Time-based blind SQLi primitive"),
    (re.compile(r"<\s*script[^>]*>|javascript:|onerror\s*=|onload\s*=", re.IGNORECASE), "CROSS_SITE_SCRIPTING", "Cross-site scripting (XSS) script/event vector"),
    (re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/).*(?:etc/passwd|win\.ini|windows/system32|boot\.ini)", re.IGNORECASE), "DIRECTORY_TRAVERSAL", "Path traversal / local file inclusion (LFI)"),
    (re.compile(r"(?:\.\./|\.\.\\){2,}", re.IGNORECASE), "DIRECTORY_TRAVERSAL", "Deep relative directory climbing traversal"),
]

SCANNER_USER_AGENTS = [
    ("sqlmap", "Automated SQL injection tool (sqlmap)"),
    ("nikto", "Web vulnerability scanner (Nikto)"),
    ("nmap", "Network and web port scanner (Nmap)"),
    ("masscan", "High-speed port scanner (Masscan)"),
    ("dirbuster", "Directory brute force scanner (DirBuster)"),
    ("gobuster", "Directory enumeration tool (Gobuster)"),
    ("wpscan", "WordPress vulnerability scanner (WPScan)"),
    ("hydra", "Network logon brute-forcer (THC-Hydra)"),
]

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog_timestamp(date_str: str, year: int = 2026, tz_offset_hours: int = 0) -> Optional[datetime]:
    """Parse standard syslog date (e.g. 'Oct 14 02:15:30') with given year and tz offset."""
    parts = date_str.split()
    if len(parts) != 3:
        return None
    month_str, day_str, time_str = parts[0], parts[1], parts[2]
    month = MONTH_MAP.get(month_str)
    if not month:
        return None
    try:
        day = int(day_str)
        hh, mm, ss = (int(x) for x in time_str.split(":"))
        tz = timezone(timedelta(hours=tz_offset_hours))
        dt = datetime(year, month, day, hh, mm, ss, tzinfo=tz)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def parse_web_timestamp(date_str: str) -> Optional[datetime]:
    """Parse web access log timestamp: '10/Oct/2026:13:55:36 +0000'."""
    try:
        dt = datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def parse_log_stream(
    raw_text: str,
    log_format: str = "auth.log",
    year_assumption: int = 2026,
    tz_offset_hours: int = 0,
) -> List[Dict[str, Any]]:
    """
    Parse lines from log text into structured event candidate dictionaries.
    Retains exact 1-based line numbers and raw verbatim line strings.
    """
    records: List[Dict[str, Any]] = []
    lines = raw_text.splitlines()

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        if log_format == "auth.log":
            rec = _parse_auth_line(idx, raw_line, year_assumption, tz_offset_hours)
            if rec:
                records.append(rec)
        elif log_format in ("web.log", "apache", "nginx"):
            rec = _parse_web_line(idx, raw_line)
            if rec:
                records.append(rec)
        else:
            # Generic fallback line parse
            records.append({
                "line_no": idx,
                "timestamp_utc": None,
                "dt_obj": None,
                "source_type": "generic.log",
                "src_ip": None,
                "username": None,
                "action": "LOG_ENTRY",
                "raw_line": raw_line,
                "extra": {},
            })

    return records


def _parse_auth_line(line_no: int, raw_line: str, year: int, tz_offset_hours: int) -> Optional[Dict[str, Any]]:
    """Parse single SSH auth.log line."""
    # 1. Extract timestamp
    dt_obj: Optional[datetime] = None
    m_syslog = RE_SYSLOG_DATE.match(raw_line)
    if m_syslog:
        dt_obj = parse_syslog_timestamp(m_syslog.group(1), year=year, tz_offset_hours=tz_offset_hours)
    else:
        m_iso = RE_ISO_DATE.match(raw_line)
        if m_iso:
            try:
                clean_iso = m_iso.group(1).replace(" ", "T")
                dt_obj = datetime.fromisoformat(clean_iso).astimezone(timezone.utc)
            except Exception:
                pass

    timestamp_utc = dt_obj.isoformat() if dt_obj else None

    # 2. Extract action, user, and IP
    src_ip = None
    username = None
    action = "INFO"

    m_fail = RE_SSH_FAILED.search(raw_line)
    if m_fail:
        username = m_fail.group(1)
        src_ip = m_fail.group(2)
        action = "SSH_AUTH_FAIL"
    else:
        m_acc = RE_SSH_ACCEPTED.search(raw_line)
        if m_acc:
            username = m_acc.group(1)
            src_ip = m_acc.group(2)
            action = "SSH_AUTH_SUCCESS"
        else:
            m_inv = RE_SSH_INVALID_USER.search(raw_line)
            if m_inv:
                username = m_inv.group(1)
                src_ip = m_inv.group(2)
                action = "SSH_INVALID_USER"

    return {
        "line_no": line_no,
        "timestamp_utc": timestamp_utc,
        "dt_obj": dt_obj,
        "source_type": "auth.log",
        "src_ip": src_ip,
        "username": username,
        "action": action,
        "raw_line": raw_line,
        "extra": {},
    }


def _parse_web_line(line_no: int, raw_line: str) -> Optional[Dict[str, Any]]:
    """Parse single Apache / Nginx combined access log line."""
    m = RE_WEB_ACCESS.match(raw_line)
    if not m:
        return None

    src_ip = m.group(1)
    username_raw = m.group(2)
    username = username_raw if username_raw != "-" else None
    ts_str = m.group(3)
    http_method = m.group(4)
    uri = m.group(5)
    status_code = m.group(6)
    user_agent = m.group(9) or ""

    dt_obj = parse_web_timestamp(ts_str)
    timestamp_utc = dt_obj.isoformat() if dt_obj else None

    return {
        "line_no": line_no,
        "timestamp_utc": timestamp_utc,
        "dt_obj": dt_obj,
        "source_type": "web.log",
        "src_ip": src_ip,
        "username": username,
        "action": f"HTTP_{status_code}",
        "raw_line": raw_line,
        "extra": {
            "method": http_method,
            "uri": uri,
            "status_code": status_code,
            "user_agent": user_agent,
        },
    }


def detect_threat_findings(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Apply rule-based heuristics on normalized log records:
    1. SUCCESS_AFTER_FAILURES (Critical)
    2. BRUTE_FORCE (High) - sliding 5-min window >= 10 failures
    3. PASSWORD_SPRAYING (High) - >= 5 distinct usernames targeted by single host
    4. ODD_HOUR_LOGIN (Medium) - successful login between 00:00 and 05:00 UTC
    5. WEB_ATTACK_SIGNATURE (High) - SQLi, XSS, Path Traversal
    6. SCANNER_USER_AGENT (Medium/High) - Automated security scanner user-agents
    """
    findings: List[Dict[str, Any]] = []

    # Filter auth records and web records
    auth_records = [r for r in records if r["source_type"] == "auth.log"]
    web_records = [r for r in records if r["source_type"] == "web.log"]

    # --------------------------------------------------------------------------
    # Rule 1 & 2 & 3: SSH Authentication Correlations
    # --------------------------------------------------------------------------
    by_ip_auth: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in auth_records:
        if r.get("src_ip"):
            by_ip_auth[r["src_ip"]].append(r)

    for ip, events in by_ip_auth.items():
        # Track failures before any success
        failures: List[Dict[str, Any]] = []
        successes: List[Dict[str, Any]] = []
        success_after_failure_lines: List[int] = []

        for ev in events:
            if ev["action"] in ("SSH_AUTH_FAIL", "SSH_INVALID_USER"):
                failures.append(ev)
            elif ev["action"] == "SSH_AUTH_SUCCESS":
                successes.append(ev)
                if len(failures) >= 3:
                    # Flag SUCCESS_AFTER_FAILURES
                    # Include the recent failures and this success
                    fail_lines = [f["line_no"] for f in failures[-10:]]
                    success_after_failure_lines.extend(fail_lines + [ev["line_no"]])

        # Rule 1: SUCCESS_AFTER_FAILURES (Critical)
        if success_after_failure_lines:
            distinct_lines = sorted(list(set(success_after_failure_lines)))
            first_ev = events[0]
            last_ev = events[-1]
            findings.append({
                "rule": "SUCCESS_AFTER_FAILURES",
                "severity": "Critical",
                "src_ip": ip,
                "count": len(distinct_lines),
                "first_seen": first_ev.get("timestamp_utc"),
                "last_seen": last_ev.get("timestamp_utc"),
                "evidence_lines": f"Suspicious authentication compromise: Host {ip} succeeded in SSH authentication after {len(failures)} failed attempts. Review lines: {distinct_lines[:15]}",
                "line_numbers": distinct_lines,
            })

        # Rule 2: BRUTE_FORCE (Sliding 5-min window >= 10 failures)
        # Sort failures by timestamp if available, else by line_no
        sorted_failures = [f for f in failures if f.get("dt_obj")]
        if len(sorted_failures) >= 10:
            bf_detected = False
            bf_lines: set = set()
            for i in range(len(sorted_failures)):
                window = [sorted_failures[i]]
                t0 = sorted_failures[i]["dt_obj"]
                for j in range(i + 1, len(sorted_failures)):
                    t1 = sorted_failures[j]["dt_obj"]
                    if (t1 - t0).total_seconds() <= 300:
                        window.append(sorted_failures[j])
                    else:
                        break
                if len(window) >= 10:
                    bf_detected = True
                    for item in window:
                        bf_lines.add(item["line_no"])

            if bf_detected:
                sorted_bf_lines = sorted(list(bf_lines))
                findings.append({
                    "rule": "BRUTE_FORCE",
                    "severity": "High",
                    "src_ip": ip,
                    "count": len(sorted_bf_lines),
                    "first_seen": sorted_failures[0].get("timestamp_utc"),
                    "last_seen": sorted_failures[-1].get("timestamp_utc"),
                    "evidence_lines": f"High-volume authentication brute-force detected from {ip} with {len(sorted_bf_lines)} failures within sliding 5-minute windows. Review lines: {sorted_bf_lines[:15]}",
                    "line_numbers": sorted_bf_lines,
                })
        elif len(failures) >= 10:
            # Fallback if timestamps could not be parsed: line proximity
            all_fail_lines = [f["line_no"] for f in failures]
            findings.append({
                "rule": "BRUTE_FORCE",
                "severity": "High",
                "src_ip": ip,
                "count": len(all_fail_lines),
                "first_seen": failures[0].get("timestamp_utc"),
                "last_seen": failures[-1].get("timestamp_utc"),
                "evidence_lines": f"Repeated authentication failures ({len(all_fail_lines)}) observed from {ip}. Review lines: {all_fail_lines[:15]}",
                "line_numbers": all_fail_lines,
            })

        # Rule 3: PASSWORD_SPRAYING (>= 5 distinct usernames targeted)
        targeted_users = {f["username"] for f in failures if f.get("username")}
        if len(targeted_users) >= 5:
            spray_lines = [f["line_no"] for f in failures]
            findings.append({
                "rule": "PASSWORD_SPRAYING",
                "severity": "High",
                "src_ip": ip,
                "count": len(spray_lines),
                "first_seen": failures[0].get("timestamp_utc"),
                "last_seen": failures[-1].get("timestamp_utc"),
                "evidence_lines": f"Password spraying pattern detected from {ip} targeting {len(targeted_users)} distinct accounts ({', '.join(list(targeted_users)[:6])}). Review lines: {spray_lines[:15]}",
                "line_numbers": spray_lines,
            })

        # Rule 4: ODD_HOUR_LOGIN (00:00 - 05:00 UTC)
        for s in successes:
            dt = s.get("dt_obj")
            if dt and (0 <= dt.hour < 5):
                findings.append({
                    "rule": "ODD_HOUR_LOGIN",
                    "severity": "Medium",
                    "src_ip": ip,
                    "count": 1,
                    "first_seen": s.get("timestamp_utc"),
                    "last_seen": s.get("timestamp_utc"),
                    "evidence_lines": f"Off-hours administrative login occurred at {s['timestamp_utc']} (00:00-05:00 UTC window) for user '{s.get('username')}' from {ip}. Review line: {s['line_no']}",
                    "line_numbers": [s["line_no"]],
                })

    # --------------------------------------------------------------------------
    # Rule 5 & 6: Web Attack Signatures and Scanner User-Agents
    # --------------------------------------------------------------------------
    web_attacks_by_ip: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)
    scanners_by_ip: Dict[str, List[Tuple[int, str]]] = defaultdict(list)

    for w in web_records:
        uri = w["extra"].get("uri", "")
        decoded_uri = urllib.parse.unquote_plus(uri)
        ua = w["extra"].get("user_agent", "")
        line_num = w["line_no"]
        ip = w["src_ip"]

        # Check web attack signatures (raw and URL-decoded)
        for pattern, sig_name, sig_desc in WEB_ATTACK_PATTERNS:
            if pattern.search(uri) or pattern.search(decoded_uri):
                web_attacks_by_ip[ip].append((line_num, sig_name, sig_desc))
                break

        # Check scanner user-agents
        ua_lower = ua.lower()
        for scanner_sig, scanner_desc in SCANNER_USER_AGENTS:
            if scanner_sig in ua_lower:
                scanners_by_ip[ip].append((line_num, scanner_desc))
                break

    for ip, attacks in web_attacks_by_ip.items():
        attack_lines = sorted(list({a[0] for a in attacks}))
        sig_types = sorted(list({a[1] for a in attacks}))
        findings.append({
            "rule": "WEB_ATTACK_SIGNATURE",
            "severity": "High",
            "src_ip": ip,
            "count": len(attack_lines),
            "first_seen": None,
            "last_seen": None,
            "evidence_lines": f"Web application attack patterns ({', '.join(sig_types)}) identified from host {ip}. Suspicious payloads in {len(attack_lines)} requests. Review lines: {attack_lines[:15]}",
            "line_numbers": attack_lines,
        })

    for ip, scans in scanners_by_ip.items():
        scan_lines = sorted(list({s[0] for s in scans}))
        tools_detected = sorted(list({s[1] for s in scans}))
        findings.append({
            "rule": "SCANNER_USER_AGENT",
            "severity": "Medium",
            "src_ip": ip,
            "count": len(scan_lines),
            "first_seen": None,
            "last_seen": None,
            "evidence_lines": f"Automated vulnerability scanning client signature ({tools_detected[0]}) identified from host {ip}. Review lines: {scan_lines[:15]}",
            "line_numbers": scan_lines,
        })

    return findings


def analyze_log_evidence(
    case_id: int,
    evidence_id: int,
    log_format: str = "auth.log",
    year_assumption: int = 2026,
    tz_offset_hours: int = 0,
    acting_user_id: Optional[int] = None,
    vault_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Execute complete Log Analyser pipeline on evidence item:
    1. Decrypt plaintext evidence bytes from vault.
    2. Parse lines according to chosen log_format with year and timezone assumptions.
    3. Run threat detection heuristics.
    4. Sync events, iocs, and findings into SQLite database.
    5. Return analysis summary and findings list.
    """
    ev = get_evidence_details(evidence_id)
    if not ev or ev["case_id"] != case_id:
        raise ValueError("Evidence item not found or does not belong to case.")

    from flask import current_app
    v_dir = vault_dir or Path(current_app.config["VAULT_DIR"])

    evidence_bytes, display_name, _ = verify_and_decrypt_evidence(
        evidence_id=evidence_id,
        vault_dir=v_dir,
        acting_user_id=acting_user_id,
        action="LOG_ANALYSIS",
    )

    raw_text = evidence_bytes.decode("utf-8", errors="replace")

    # 1. Parse log stream
    records = parse_log_stream(
        raw_text=raw_text,
        log_format=log_format,
        year_assumption=year_assumption,
        tz_offset_hours=tz_offset_hours,
    )

    # 2. Run detection rules
    findings = detect_threat_findings(records)

    now_utc = datetime.now(timezone.utc).isoformat()

    # 3. Database Sync: Clean prior log events, iocs, findings for this evidence
    execute_db("DELETE FROM events WHERE evidence_id = ? AND source_type IN ('auth.log', 'web.log', 'generic.log')", (evidence_id,))
    execute_db("DELETE FROM iocs WHERE first_evidence_id = ? AND source = 'log_analyser'", (evidence_id,))
    execute_db(
        """
        DELETE FROM findings
        WHERE evidence_id = ? AND rule IN (
            'SUCCESS_AFTER_FAILURES', 'BRUTE_FORCE', 'PASSWORD_SPRAYING',
            'ODD_HOUR_LOGIN', 'WEB_ATTACK_SIGNATURE', 'SCANNER_USER_AGENT'
        )
        """,
        (evidence_id,),
    )

    # Insert events (capped at 10,000 for timeline responsiveness)
    for r in records[:10000]:
        execute_db(
            """
            INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, username, action, raw_line)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                evidence_id,
                r["line_no"],
                r["timestamp_utc"] or now_utc,
                r["source_type"],
                r.get("src_ip"),
                r.get("username"),
                r["action"],
                r["raw_line"],
            ),
        )

    # Insert findings
    for f in findings:
        execute_db(
            """
            INSERT INTO findings (case_id, evidence_id, rule, severity, src_ip, count, first_seen, last_seen, evidence_lines, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open')
            """,
            (
                case_id,
                evidence_id,
                f["rule"],
                f["severity"],
                f.get("src_ip"),
                f.get("count", 1),
                f.get("first_seen") or now_utc,
                f.get("last_seen") or now_utc,
                f["evidence_lines"],
            ),
        )

    # Insert IOCs for suspicious source IPs
    flagged_ips = {f["src_ip"] for f in findings if f.get("src_ip")}
    for ip in flagged_ips:
        if ip and ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
            execute_db(
                """
                INSERT OR IGNORE INTO iocs (case_id, type, value, first_evidence_id, verdict, source)
                VALUES (?, 'ipv4', ?, ?, 'Suspicious', 'log_analyser')
                """,
                (case_id, ip, evidence_id),
            )

    return {
        "evidence_id": evidence_id,
        "display_name": display_name,
        "log_format": log_format,
        "year_assumption": year_assumption,
        "tz_offset_hours": tz_offset_hours,
        "total_lines_parsed": len(records),
        "events_count": min(len(records), 10000),
        "findings": findings,
        "flagged_ips": list(flagged_ips),
    }


def get_stored_log_summary(case_id: int, evidence_id: int) -> Dict[str, Any]:
    """Retrieve existing events, findings, and IOCs for log evidence."""
    events = query_db(
        """
        SELECT id, line_no, timestamp_utc, source_type, src_ip, username, action, raw_line
        FROM events
        WHERE evidence_id = ? AND source_type IN ('auth.log', 'web.log', 'generic.log')
        ORDER BY line_no ASC
        LIMIT 100
        """,
        (evidence_id,),
    )
    findings = query_db(
        """
        SELECT id, rule, severity, src_ip, count, first_seen, last_seen, evidence_lines, status
        FROM findings
        WHERE evidence_id = ? AND rule IN (
            'SUCCESS_AFTER_FAILURES', 'BRUTE_FORCE', 'PASSWORD_SPRAYING',
            'ODD_HOUR_LOGIN', 'WEB_ATTACK_SIGNATURE', 'SCANNER_USER_AGENT'
        )
        ORDER BY
            CASE severity
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5
            END, id ASC
        """,
        (evidence_id,),
    )
    iocs = query_db(
        """
        SELECT id, type, value, verdict, source
        FROM iocs
        WHERE first_evidence_id = ? AND source = 'log_analyser'
        ORDER BY id ASC
        """,
        (evidence_id,),
    )
    return {
        "events": [dict(e) for e in events],
        "findings": [dict(f) for f in findings],
        "iocs": [dict(i) for i in iocs],
    }


def get_raw_log_lines_by_numbers(
    case_id: int,
    evidence_id: int,
    line_numbers: List[int],
    vault_dir: Optional[Path] = None,
    acting_user_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Safely extract verbatim raw log lines from the encrypted vault file by line numbers.
    Preserves cryptographic integrity and avoids arbitrary file exposure.
    """
    from flask import current_app
    v_dir = vault_dir or Path(current_app.config["VAULT_DIR"])

    evidence_bytes, _, _ = verify_and_decrypt_evidence(
        evidence_id=evidence_id,
        vault_dir=v_dir,
        acting_user_id=acting_user_id,
        action="LOG_LINE_INSPECTION",
    )

    all_lines = evidence_bytes.decode("utf-8", errors="replace").splitlines()
    target_set = set(line_numbers)

    result = []
    for idx, line in enumerate(all_lines, start=1):
        if idx in target_set:
            result.append({"line_no": idx, "content": line})

    return result
