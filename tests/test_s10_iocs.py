"""
Tests for Section S10: IOC Extractor & Offline Reputation.
Covers:
- Regex and rule-based extraction (IPv4, domains, URLs, emails, SHA-256, MD5)
- Filtering out RFC-1918 private/loopback IPs, single-label domains, and internal suffixes
- Defanging logic (defang for safe display, never raw hyperlinks)
- Deduplication and database upsert
- Route access control: @case_member_required (404), @role_required (Reviewer 403)
- CSV export generation
- Zero outbound network calls (offline-first integrity)
"""

import io
from pathlib import Path
from unittest.mock import patch

import pytest
from werkzeug.datastructures import FileStorage

from app import create_app
from app.db import init_db, query_db, execute_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.evidence.service import intake_evidence
from app.modules.iocs.service import (
    defang,
    extract_iocs_from_text,
    upsert_ioc,
    extract_and_store_iocs,
    get_case_iocs,
    export_iocs_csv,
)


@pytest.fixture
def ioc_env(tmp_path):
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vault"
    db_path = data_dir / "db" / "forensix.db"
    master_key = data_dir / "keys" / "master.key"
    work_dir = data_dir / "work"

    app = create_app({
        "TESTING": True,
        "DATA_DIR": str(data_dir),
        "VAULT_DIR": str(vault_dir),
        "DB_DIR": str(data_dir / "db"),
        "KEYS_DIR": str(data_dir / "keys"),
        "LOGS_DIR": str(data_dir / "logs"),
        "WORK_DIR": str(work_dir),
        "DATABASE_PATH": str(db_path),
        "MASTER_KEY_PATH": str(master_key),
        "WTF_CSRF_ENABLED": False,
        "ALLOW_LAN": False,
        "HOST": "127.0.0.1",
        "PORT": 5000,
        "SECRET_KEY": "test_secret_key_forensix_section10_iocs",
        "EXTERNAL_LOOKUPS": False,
    })

    with app.app_context():
        init_db(db_path)
        lead_id = create_user("Lead User", "lead_ioc", "Lead", "LeadPass123!")
        analyst_id = create_user("Analyst User", "analyst_ioc", "Analyst", "AnalystPass123!")
        reviewer_id = create_user("Reviewer User", "reviewer_ioc", "Reviewer", "ReviewerPass123!")
        outsider_id = create_user("Outsider User", "outsider_ioc", "Analyst", "OutsiderPass123!")

        case_id = create_case("IOC Incident Alpha", "Investigating malware command and control", "Critical", lead_id)
        assign_member(case_id, analyst_id, lead_id)
        assign_member(case_id, reviewer_id, lead_id)

    return {
        "app": app,
        "lead_id": lead_id,
        "analyst_id": analyst_id,
        "reviewer_id": reviewer_id,
        "outsider_id": outsider_id,
        "case_id": case_id,
        "vault_dir": vault_dir,
        "work_dir": work_dir,
    }


def test_extract_iocs_from_text():
    """Verify extraction of all supported IOC types from sample log/text content."""
    sample_text = """
    Incident Report:
    Malicious host 198.51.100.45 contacted C2 at http://malware-command.xyz/beacon.php.
    Secondary server: https://evil-c2.net:8443/api/v1/download
    Phishing emails sent from badactor@phish-corp.org to victim@internal.local.
    Attacker domain identified as dropzone-exfil.biz.
    SHA-256 payload: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    MD5 dropped file: 5d41402abc4b2a76b9719d911017c592
    """
    results = extract_iocs_from_text(sample_text)
    types = {r["type"] for r in results}
    values = {r["value"] for r in results}

    assert "ipv4" in types
    assert "198.51.100.45" in values

    assert "url" in types
    assert "http://malware-command.xyz/beacon.php" in values
    assert "https://evil-c2.net:8443/api/v1/download" in values

    assert "email" in types
    assert "badactor@phish-corp.org" in values

    assert "domain" in types
    assert "dropzone-exfil.biz" in values

    assert "hash_sha256" in types
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in values

    assert "hash_md5" in types
    assert "5d41402abc4b2a76b9719d911017c592" in values


def test_private_ips_and_internal_domains_excluded():
    """Verify RFC-1918 private IPs, loopback, and internal/single-label domains are ignored."""
    text = """
    Connecting from 127.0.0.1 to 10.0.0.5 and 192.168.1.100.
    DMZ host at 172.16.5.20 and link-local 169.254.1.1.
    Internal hostnames: localhost, server.local, app.internal, testbox.
    Legitimate public: 203.0.113.88 and external.co.uk
    """
    results = extract_iocs_from_text(text)
    extracted_ips = [r["value"] for r in results if r["type"] == "ipv4"]
    extracted_domains = [r["value"] for r in results if r["type"] == "domain"]

    # Private IPs excluded
    assert "127.0.0.1" not in extracted_ips
    assert "10.0.0.5" not in extracted_ips
    assert "192.168.1.100" not in extracted_ips
    assert "172.16.5.20" not in extracted_ips
    assert "169.254.1.1" not in extracted_ips

    # Public IP captured
    assert "203.0.113.88" in extracted_ips

    # Internal domains excluded
    assert "localhost" not in extracted_domains
    assert "server.local" not in extracted_domains
    assert "app.internal" not in extracted_domains
    assert "testbox" not in extracted_domains

    # Real public domain captured
    assert "external.co.uk" in extracted_domains


def test_defang_formats():
    """Verify defanging sanitizes indicators so they cannot be accidentally clicked."""
    assert defang("198.51.100.77", "ipv4") == "198[.]51[.]100[.]77"
    assert defang("evil-domain.com", "domain") == "evil-domain[.]com"
    assert defang("admin@attacker.org", "email") == "admin@attacker[.]org"

    # URL defanging
    url_defanged = defang("http://badsite.com/payload.exe", "url")
    assert "http" not in url_defanged or "hxxp" in url_defanged
    assert "[.]" in url_defanged

    # Hashes unaltered
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert defang(h, "hash_sha256") == h


def test_upsert_deduplication(ioc_env):
    """Verify upsert_ioc enforces uniqueness and deduplicates identical indicators."""
    app = ioc_env["app"]
    case_id = ioc_env["case_id"]

    with app.app_context():
        id1 = upsert_ioc(case_id, "ipv4", "203.0.113.50", None, "test")
        id2 = upsert_ioc(case_id, "ipv4", "203.0.113.50", None, "test")
        assert id1 == id2

        rows = query_db("SELECT id FROM iocs WHERE case_id = ? AND type = 'ipv4' AND value = '203.0.113.50'", (case_id,))
        assert len(rows) == 1


def test_extract_and_store_from_events(ioc_env):
    """Verify extracting IOCs from stored events of an evidence item."""
    app = ioc_env["app"]
    case_id = ioc_env["case_id"]
    lead_id = ioc_env["lead_id"]
    vault_dir = ioc_env["vault_dir"]
    work_dir = ioc_env["work_dir"]

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(b"dummy log"), filename="sample.log")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="auth.log",
        )

        # Insert some events
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, action, raw_line)
               VALUES (?, ?, 1, '2026-10-14T02:00:00Z', 'auth.log', '198.51.100.99', 'SSH_FAIL',
                       'Failed password for admin from 198.51.100.99 port 22 http://exfil-site.org/callback.php')""",
            (case_id, ev_id),
        )

        summary = extract_and_store_iocs(
            case_id=case_id,
            evidence_id=ev_id,
            text_content="Failed password for admin from 198.51.100.99 port 22 http://exfil-site.org/callback.php",
            source="extractor",
        )
        assert summary["total"] >= 2
        assert "ipv4" in summary["by_type"]

        case_iocs = get_case_iocs(case_id)
        assert any(i["value"] == "198.51.100.99" for i in case_iocs)


def test_ioc_routes_rbac_and_views(ioc_env):
    """Verify access controls: non-member gets 404, Reviewer denied POST (403), member gets 200."""
    app = ioc_env["app"]
    case_id = ioc_env["case_id"]
    analyst_id = ioc_env["analyst_id"]
    reviewer_id = ioc_env["reviewer_id"]
    outsider_id = ioc_env["outsider_id"]

    client = app.test_client()

    # 1. Outsider gets 404
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/iocs")
    assert resp.status_code == 404

    # 2. Member gets 200
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/iocs")
    assert resp.status_code == 200
    assert b"Indicators of Compromise" in resp.data

    # 3. Reviewer cannot POST to extraction route -> 403
    with client.session_transaction() as sess:
        sess["_user_id"] = str(reviewer_id)
        sess["_fresh"] = True
    resp_rev = client.post(f"/cases/{case_id}/iocs/extract/999")
    assert resp_rev.status_code == 403


def test_export_csv_and_defanging(ioc_env):
    """Verify CSV export contains defanged indicators and correct headers."""
    app = ioc_env["app"]
    case_id = ioc_env["case_id"]
    analyst_id = ioc_env["analyst_id"]

    with app.app_context():
        upsert_ioc(case_id, "ipv4", "203.0.113.19", None, "unit_test")
        upsert_ioc(case_id, "domain", "c2-server.com", None, "unit_test")

        csv_str = export_iocs_csv(case_id)
        assert "Value (Defanged)" in csv_str
        assert "203[.]0[.]113[.]19" in csv_str
        assert "c2-server[.]com" in csv_str

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/iocs/export.csv")
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert b"203[.]0[.]113[.]19" in resp.data


def test_no_network_calls_when_lookups_disabled(ioc_env):
    """Integrity check: verify that no outbound HTTP socket or request is made during IOC operations."""
    app = ioc_env["app"]
    case_id = ioc_env["case_id"]

    with patch("socket.socket.connect") as mock_connect, \
         patch("urllib.request.urlopen") as mock_urlopen:

        with app.app_context():
            text = "Suspicious traffic to 198.51.100.200 and http://attack.org"
            extract_and_store_iocs(case_id, None, text, source="offline_test")
            iocs = get_case_iocs(case_id)
            assert len(iocs) >= 1

        mock_connect.assert_not_called()
        mock_urlopen.assert_not_called()
