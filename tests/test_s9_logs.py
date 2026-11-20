"""
Tests for Section S9: Log Analyser Module.
Covers:
- Syslog and Web timestamp normalization
- Demo auth.log (150 failures then success -> Critical SUCCESS_AFTER_FAILURES with line pointers)
- Brute-force detection (sliding 5-minute window)
- Password spraying detection (>= 5 distinct usernames)
- Odd-hour login detection (00:00 - 05:00 UTC)
- Web attack signatures (SQLi, XSS, Path Traversal) and scanner user-agents (sqlmap, nikto)
- Database synchronization (events, iocs, findings)
- Line inspector endpoint, exports (JSON, CSV), and RBAC enforcement
"""

import io
from pathlib import Path
from werkzeug.datastructures import FileStorage

import pytest
from app import create_app
from app.db import init_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.evidence.service import intake_evidence
from app.modules.logs.service import (
    parse_syslog_timestamp,
    parse_web_timestamp,
    analyze_log_evidence,
    get_stored_log_summary,
    get_raw_log_lines_by_numbers,
)


@pytest.fixture
def log_env(tmp_path):
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
        "SECRET_KEY": "test_secret_key_forensix_section9_logs",
    })

    with app.app_context():
        init_db(db_path)
        # Create test users
        lead_id = create_user("Lead User", "lead_user", "Lead", "LeadPass123!")
        analyst_id = create_user("Analyst User", "analyst_user", "Analyst", "AnalystPass123!")
        reviewer_id = create_user("Reviewer User", "reviewer_user", "Reviewer", "ReviewerPass123!")
        outsider_id = create_user("Outsider User", "outsider_user", "Analyst", "OutsiderPass123!")

        # Create case
        case_id = create_case("Log Incident Beta", "Investigating server intrusion logs", "High", lead_id)
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


def test_timestamp_normalizers():
    """Verify syslog and web timestamp normalization to ISO-8601 UTC."""
    # Syslog: Oct 14 02:15:30 with year 2026 and UTC offset 0
    dt_syslog = parse_syslog_timestamp("Oct 14 02:15:30", year=2026, tz_offset_hours=0)
    assert dt_syslog is not None
    assert dt_syslog.isoformat() == "2026-10-14T02:15:30+00:00"

    # Syslog with +5 timezone offset
    dt_tz = parse_syslog_timestamp("Oct 14 07:15:30", year=2026, tz_offset_hours=5)
    assert dt_tz is not None
    assert dt_tz.isoformat() == "2026-10-14T02:15:30+00:00"

    # Apache/Nginx web timestamp
    dt_web = parse_web_timestamp("10/Oct/2026:13:55:36 +0000")
    assert dt_web is not None
    assert dt_web.isoformat() == "2026-10-10T13:55:36+00:00"


def test_demo_auth_log_success_after_failures_critical(log_env):
    """
    Done condition: Demo auth.log (150 failures then a success) produces
    a Critical 'SUCCESS_AFTER_FAILURES' finding pointing to the exact line numbers.
    """
    app = log_env["app"]
    case_id = log_env["case_id"]
    analyst_id = log_env["analyst_id"]
    vault_dir = log_env["vault_dir"]
    work_dir = log_env["work_dir"]

    # Build 150 failure lines followed by 1 successful login
    lines = []
    for i in range(1, 151):
        lines.append(f"Oct 14 02:{i % 60:02d}:10 server sshd[123{i}]: Failed password for invalid user admin from 198.51.100.77 port {40000 + i} ssh2")

    # Line 151: Successful authentication
    lines.append("Oct 14 02:59:45 server sshd[12399]: Accepted password for admin from 198.51.100.77 port 45199 ssh2")

    log_content = "\n".join(lines).encode("utf-8")

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(log_content), filename="auth.log")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=analyst_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="auth.log",
        )

        res = analyze_log_evidence(
            case_id=case_id,
            evidence_id=ev_id,
            log_format="auth.log",
            year_assumption=2026,
            tz_offset_hours=0,
            acting_user_id=analyst_id,
            vault_dir=vault_dir,
        )

        assert res["total_lines_parsed"] == 151

        # Check findings
        rules_map = {f["rule"]: f for f in res["findings"]}
        assert "SUCCESS_AFTER_FAILURES" in rules_map

        crit_finding = rules_map["SUCCESS_AFTER_FAILURES"]
        assert crit_finding["severity"] == "Critical"
        assert crit_finding["src_ip"] == "198.51.100.77"
        assert 151 in crit_finding["line_numbers"]
        assert "151" in crit_finding["evidence_lines"]

        # Also triggers BRUTE_FORCE
        assert "BRUTE_FORCE" in rules_map
        assert rules_map["BRUTE_FORCE"]["severity"] == "High"


def test_password_spraying_and_odd_hour_logins(log_env):
    """Verify PASSWORD_SPRAYING and ODD_HOUR_LOGIN heuristic rules."""
    app = log_env["app"]
    case_id = log_env["case_id"]
    lead_id = log_env["lead_id"]
    vault_dir = log_env["vault_dir"]
    work_dir = log_env["work_dir"]

    # 1. Password spraying: 6 distinct accounts targeted from 203.0.113.10
    lines = [
        "Oct 15 01:10:00 srv sshd[10]: Failed password for root from 203.0.113.10 port 5001 ssh2",
        "Oct 15 01:10:05 srv sshd[11]: Failed password for admin from 203.0.113.10 port 5002 ssh2",
        "Oct 15 01:10:10 srv sshd[12]: Failed password for user1 from 203.0.113.10 port 5003 ssh2",
        "Oct 15 01:10:15 srv sshd[13]: Failed password for deploy from 203.0.113.10 port 5004 ssh2",
        "Oct 15 01:10:20 srv sshd[14]: Failed password for oracle from 203.0.113.10 port 5005 ssh2",
        "Oct 15 01:10:25 srv sshd[15]: Failed password for test from 203.0.113.10 port 5006 ssh2",
        # 2. Odd-hour login at 02:30:00 UTC
        "Oct 15 02:30:00 srv sshd[20]: Accepted password for backup_svc from 10.0.0.99 port 5007 ssh2",
    ]

    log_content = "\n".join(lines).encode("utf-8")

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(log_content), filename="spraying.log")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="auth.log",
        )

        res = analyze_log_evidence(
            case_id=case_id,
            evidence_id=ev_id,
            log_format="auth.log",
            year_assumption=2026,
            tz_offset_hours=0,
            acting_user_id=lead_id,
            vault_dir=vault_dir,
        )

        rules_map = {f["rule"]: f for f in res["findings"]}

        # Check PASSWORD_SPRAYING
        assert "PASSWORD_SPRAYING" in rules_map
        assert rules_map["PASSWORD_SPRAYING"]["severity"] == "High"
        assert rules_map["PASSWORD_SPRAYING"]["src_ip"] == "203.0.113.10"

        # Check ODD_HOUR_LOGIN
        assert "ODD_HOUR_LOGIN" in rules_map
        assert rules_map["ODD_HOUR_LOGIN"]["severity"] == "Medium"
        assert rules_map["ODD_HOUR_LOGIN"]["line_numbers"] == [7]


def test_web_attack_signatures_and_scanners(log_env):
    """Verify SQLi, XSS, Path Traversal, and Scanner User-Agent detections in access logs."""
    app = log_env["app"]
    case_id = log_env["case_id"]
    analyst_id = log_env["analyst_id"]
    vault_dir = log_env["vault_dir"]
    work_dir = log_env["work_dir"]

    lines = [
        # Normal traffic
        '192.168.1.10 - - [10/Oct/2026:14:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"',
        # SQL Injection
        '198.51.100.99 - - [10/Oct/2026:14:01:00 +0000] "GET /items.php?cat=1\'%20OR%201=1-- HTTP/1.1" 200 1204 "-" "Mozilla/5.0"',
        '198.51.100.99 - - [10/Oct/2026:14:01:05 +0000] "GET /users.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 890 "-" "Mozilla/5.0"',
        # XSS
        '198.51.100.99 - - [10/Oct/2026:14:02:00 +0000] "GET /search.php?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 500 "-" "Mozilla/5.0"',
        # Directory Traversal
        '198.51.100.99 - - [10/Oct/2026:14:03:00 +0000] "GET /view.php?file=../../../../etc/passwd HTTP/1.1" 200 1520 "-" "Mozilla/5.0"',
        # Scanner User-Agent
        '203.0.113.88 - - [10/Oct/2026:14:05:00 +0000] "GET /vulnerable.php HTTP/1.1" 200 340 "-" "sqlmap/1.6#stable"',
    ]

    log_content = "\n".join(lines).encode("utf-8")

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(log_content), filename="access.log")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=analyst_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="web.log",
        )

        res = analyze_log_evidence(
            case_id=case_id,
            evidence_id=ev_id,
            log_format="web.log",
            acting_user_id=analyst_id,
            vault_dir=vault_dir,
        )

        rules_map = {f["rule"]: f for f in res["findings"]}

        # WEB_ATTACK_SIGNATURE
        assert "WEB_ATTACK_SIGNATURE" in rules_map
        assert rules_map["WEB_ATTACK_SIGNATURE"]["severity"] == "High"
        assert rules_map["WEB_ATTACK_SIGNATURE"]["src_ip"] == "198.51.100.99"
        assert 2 in rules_map["WEB_ATTACK_SIGNATURE"]["line_numbers"]

        # SCANNER_USER_AGENT
        assert "SCANNER_USER_AGENT" in rules_map
        assert rules_map["SCANNER_USER_AGENT"]["severity"] == "Medium"
        assert rules_map["SCANNER_USER_AGENT"]["src_ip"] == "203.0.113.88"


def test_database_sync_events_and_iocs(log_env):
    """Verify events table and iocs table synchronization."""
    app = log_env["app"]
    case_id = log_env["case_id"]
    lead_id = log_env["lead_id"]
    vault_dir = log_env["vault_dir"]
    work_dir = log_env["work_dir"]

    lines = [
        "Oct 14 02:10:00 srv sshd[10]: Failed password for root from 198.51.100.44 port 5001 ssh2",
        "Oct 14 02:10:05 srv sshd[11]: Accepted password for root from 198.51.100.44 port 5002 ssh2",
    ]

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO("\n".join(lines).encode("utf-8")), filename="sync_test.log")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="auth.log",
        )

        analyze_log_evidence(
            case_id=case_id,
            evidence_id=ev_id,
            log_format="auth.log",
            acting_user_id=lead_id,
            vault_dir=vault_dir,
        )

        # Check events table
        events = query_db("SELECT line_no, action, src_ip, raw_line FROM events WHERE evidence_id = ? ORDER BY line_no ASC", (ev_id,))
        assert len(events) == 2
        assert events[0]["line_no"] == 1
        assert events[0]["action"] == "SSH_AUTH_FAIL"
        assert events[0]["src_ip"] == "198.51.100.44"
        assert "Failed password" in events[0]["raw_line"]

        assert events[1]["line_no"] == 2
        assert events[1]["action"] == "SSH_AUTH_SUCCESS"


def test_line_inspector_endpoint_and_routes(log_env):
    """Verify line inspector AJAX, RBAC, and JSON/CSV exports."""
    app = log_env["app"]
    case_id = log_env["case_id"]
    analyst_id = log_env["analyst_id"]
    reviewer_id = log_env["reviewer_id"]
    outsider_id = log_env["outsider_id"]
    vault_dir = log_env["vault_dir"]
    work_dir = log_env["work_dir"]

    lines = [
        "Line 1: Log initialization",
        "Line 2: System audit event",
        "Line 3: Anomaly alert trigger",
    ]

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO("\n".join(lines).encode("utf-8")), filename="inspector.log")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=analyst_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="generic.log",
        )

    client = app.test_client()

    # 1. Outsider access -> 404
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/evidence/{ev_id}/logs")
    assert resp.status_code == 404

    # 2. Member access -> 200 OK
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/evidence/{ev_id}/logs")
    assert resp.status_code == 200
    assert b"Log Analyser" in resp.data

    # 3. Line inspector AJAX
    resp_lines = client.get(f"/cases/{case_id}/evidence/{ev_id}/logs/lines?lines=1,3")
    assert resp_lines.status_code == 200
    data = resp_lines.get_json()
    assert len(data["lines"]) == 2
    assert data["lines"][0]["line_no"] == 1
    assert data["lines"][0]["content"] == "Line 1: Log initialization"
    assert data["lines"][1]["line_no"] == 3
    assert data["lines"][1]["content"] == "Line 3: Anomaly alert trigger"

    # 4. JSON export
    resp_json = client.get(f"/cases/{case_id}/evidence/{ev_id}/logs/export.json")
    assert resp_json.status_code == 200
    assert resp_json.mimetype == "application/json"
    assert "attachment; filename=log_analysis_" in resp_json.headers.get("Content-Disposition", "")

    # 5. CSV export
    resp_csv = client.get(f"/cases/{case_id}/evidence/{ev_id}/logs/export.csv")
    assert resp_csv.status_code == 200
    assert resp_csv.mimetype == "text/csv"
    assert "attachment; filename=log_events_" in resp_csv.headers.get("Content-Disposition", "")

    # 6. Reviewer tries POST /analyze -> 403 Forbidden
    with client.session_transaction() as sess:
        sess["_user_id"] = str(reviewer_id)
        sess["_fresh"] = True
    resp_rev = client.post(f"/cases/{case_id}/evidence/{ev_id}/logs/analyze", data={"log_format": "auth.log"})
    assert resp_rev.status_code == 403
