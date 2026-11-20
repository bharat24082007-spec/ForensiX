"""
ForensiX IOC Extractor Service.
Extracts Indicators of Compromise from text using regex + validation,
stores them in the database, and provides query/export helpers.
No external network calls; reputation lookups are disabled by default.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from typing import Dict, List, Optional

from app.db import execute_db, query_db


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# IPv4 – raw octet pattern (validation done in Python)
_RE_IPV4 = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))\b"
)

# Domain names – require at least one label + TLD of 2+ chars
# Negative-lookahead to avoid matching inside email local-part
_RE_DOMAIN = re.compile(
    r"(?<![@\w])"
    r"((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,})"
    r"\b"
)

# URLs – http/https only
_RE_URL = re.compile(
    r"\b(https?://[^\s\"'<>\]\[}{|\\^`]+)"
)

# Emails
_RE_EMAIL = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
)

# SHA-256 hashes – exactly 64 hex chars (not part of a longer hex string)
_RE_SHA256 = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")

# MD5 hashes – exactly 32 hex chars
_RE_MD5 = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])")

# Private / loopback / link-local ranges to skip
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

_SKIP_DOMAINS = {"localhost"}
_SKIP_DOMAIN_SUFFIXES = (".local", ".internal", ".localdomain", ".example", ".test", ".invalid")

# TLDs that are definitely not real (single char)
_MIN_TLD_LEN = 2


# ---------------------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------------------

def defang(value: str, ioc_type: str) -> str:
    """
    Defang an IOC value for safe display.

    - ipv4   → 1[.]2[.]3[.]4
    - url    → hxxp[:]//evil[.]com/path
    - domain → evil[.]com
    - email  → user@evil[.]com (domain part defanged)
    - hashes → returned as-is (no active hyperlink risk)
    """
    if ioc_type == "ipv4":
        return value.replace(".", "[.]")

    if ioc_type == "url":
        # hxxp:// or hxxps://
        defanged = re.sub(r"^https?", lambda m: m.group(0).replace("http", "hxxp"), value, count=1)
        defanged = defanged.replace("://", "[://]", 1)
        # Defang dots in the host portion (up to first /)
        try:
            after_scheme = defanged.split("[://]", 1)[1]
            slash_pos = after_scheme.find("/")
            if slash_pos == -1:
                host_part = after_scheme
                path_part = ""
            else:
                host_part = after_scheme[:slash_pos]
                path_part = after_scheme[slash_pos:]
            host_part = host_part.replace(".", "[.]")
            return defanged.split("[://]")[0] + "[://]" + host_part + path_part
        except (IndexError, ValueError):
            return defanged

    if ioc_type == "domain":
        return value.replace(".", "[.]")

    if ioc_type == "email":
        local, _, domain = value.partition("@")
        return local + "@" + domain.replace(".", "[.]")

    # hash_sha256, hash_md5 — no active risk
    return value


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _is_private_ip(addr_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(addr_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True  # malformed → skip


def _is_skip_domain(domain: str) -> bool:
    lower = domain.lower()
    if lower in _SKIP_DOMAINS:
        return True
    if any(lower.endswith(s) for s in _SKIP_DOMAIN_SUFFIXES):
        return True
    # Must have a TLD of at least 2 chars
    parts = lower.split(".")
    if len(parts) < 2 or len(parts[-1]) < _MIN_TLD_LEN:
        return True
    return False


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_iocs_from_text(text: str) -> List[Dict]:
    """
    Extract IOCs from free text using regex and validation rules.
    Returns deduplicated list of {"type": ..., "value": ...} dicts.

    Types: ipv4, domain, url, email, hash_sha256, hash_md5
    - Private/loopback IPs excluded
    - Single-label domains, .local, .internal excluded
    - Only http/https URLs included
    - Emails: standard format
    - SHA-256: exactly 64 hex chars
    - MD5: exactly 32 hex chars (not part of a 64-char hash)
    """
    seen: set = set()
    results: List[Dict] = []

    def add(ioc_type: str, value: str) -> None:
        key = (ioc_type, value.lower())
        if key not in seen:
            seen.add(key)
            results.append({"type": ioc_type, "value": value})

    # --- Emails first (so their domains are not re-extracted as plain domains) ---
    email_domains: set = set()
    for m in _RE_EMAIL.finditer(text):
        email = m.group(1)
        add("email", email)
        _, _, domain = email.partition("@")
        email_domains.add(domain.lower())

    # --- URLs (http/https) ---
    url_hosts: set = set()
    for m in _RE_URL.finditer(text):
        url = m.group(1).rstrip(".,;:!?)")
        add("url", url)
        # Extract host from URL to avoid re-adding it as a plain domain
        try:
            after_scheme = url.split("://", 1)[1]
            host = after_scheme.split("/")[0].split(":")[0]
            url_hosts.add(host.lower())
        except (IndexError, ValueError):
            pass

    # --- IPv4 ---
    ip_strs: set = set()
    for m in _RE_IPV4.finditer(text):
        ip = m.group(1)
        if not _is_private_ip(ip):
            add("ipv4", ip)
            ip_strs.add(ip)

    # --- Domains (skip those already captured as email domains or URL hosts) ---
    for m in _RE_DOMAIN.finditer(text):
        domain = m.group(1).lower()
        if domain in email_domains or domain in url_hosts:
            continue
        if domain in ip_strs:
            continue
        if _is_skip_domain(domain):
            continue
        add("domain", domain)

    # --- SHA-256 (collect 64-hex matches first) ---
    sha256_values: set = set()
    for m in _RE_SHA256.finditer(text):
        h = m.group(1).lower()
        sha256_values.add(h)
        add("hash_sha256", h)

    # --- MD5 (32-hex not part of a 64-hex hash) ---
    for m in _RE_MD5.finditer(text):
        h = m.group(1).lower()
        # Skip if this 32-char block is a substring of a known SHA-256
        is_sub = any(h in s for s in sha256_values)
        if not is_sub:
            add("hash_md5", h)

    return results


# ---------------------------------------------------------------------------
# DB operations
# ---------------------------------------------------------------------------

def upsert_ioc(
    case_id: int,
    ioc_type: str,
    value: str,
    evidence_id: Optional[int],
    source: str = "manual",
) -> int:
    """
    INSERT OR IGNORE an IOC into the iocs table.
    Returns the row id of the IOC (existing or newly created).
    """
    execute_db(
        """
        INSERT OR IGNORE INTO iocs (case_id, type, value, first_evidence_id, verdict, source)
        VALUES (?, ?, ?, ?, 'Unknown', ?)
        """,
        (case_id, ioc_type, value, evidence_id, source),
    )
    row = query_db(
        "SELECT id FROM iocs WHERE case_id = ? AND type = ? AND value = ?",
        (case_id, ioc_type, value),
        one=True,
    )
    return row["id"] if row else -1


def extract_and_store_iocs(
    case_id: int,
    evidence_id: Optional[int],
    text_content: str,
    source: str = "extractor",
) -> Dict:
    """
    Extract IOCs from text, store in DB, and return a summary dict.
    Returns: {"total": int, "new": int, "by_type": {type: count}}
    """
    extracted = extract_iocs_from_text(text_content)
    by_type: Dict[str, int] = {}
    new_count = 0

    for ioc in extracted:
        ioc_type = ioc["type"]
        value = ioc["value"]

        # Check if already exists
        existing = query_db(
            "SELECT id FROM iocs WHERE case_id = ? AND type = ? AND value = ?",
            (case_id, ioc_type, value),
            one=True,
        )
        if not existing:
            new_count += 1

        upsert_ioc(case_id, ioc_type, value, evidence_id, source)
        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1

    return {
        "total": len(extracted),
        "new": new_count,
        "by_type": by_type,
    }


def get_case_iocs(
    case_id: int,
    filter_type: Optional[str] = None,
    filter_verdict: Optional[str] = None,
) -> List[Dict]:
    """
    Get all IOCs for a case with optional filters.
    Joins with evidence for display_name.
    """
    base = """
        SELECT i.id, i.type, i.value, i.verdict, i.source,
               e.display_name AS evidence_name, i.first_evidence_id
        FROM iocs i
        LEFT JOIN evidence e ON e.id = i.first_evidence_id
        WHERE i.case_id = ?
    """
    args: list = [case_id]

    if filter_type:
        base += " AND i.type = ?"
        args.append(filter_type)

    if filter_verdict:
        base += " AND i.verdict = ?"
        args.append(filter_verdict)

    base += " ORDER BY i.type, i.id"

    rows = query_db(base, tuple(args))
    return [dict(r) for r in rows]


def export_iocs_csv(case_id: int) -> str:
    """Generate a CSV string of all IOCs for a case."""
    iocs = get_case_iocs(case_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Type", "Value (Defanged)", "Verdict", "Source", "Evidence"])
    for ioc in iocs:
        writer.writerow([
            ioc["id"],
            ioc["type"],
            defang(ioc["value"], ioc["type"]),
            ioc["verdict"],
            ioc["source"],
            ioc.get("evidence_name") or "",
        ])
    return output.getvalue()
