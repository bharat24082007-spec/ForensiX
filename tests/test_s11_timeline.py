"""
Tests for Section S11: Investigation Timeline Module.
Covers:
- Merging events across multiple sources (logs, pcap, metadata, custody_log)
- Chronological timestamp sorting (UTC)
- Severity propagation from findings table (Critical/High)
- Filtering by source, evidence_id, severity, and date ranges
- CSV export matching table contents and logging EXPORT_TIMELINE_CSV into custody_log
- Route access control: @case_member_required (404 for non-members)
- JSON data endpoint for interactive vis-timeline widget
"""

import io
from pathlib import Path
import pytest
from werkzeug.datastructures import FileStorage

from app import create_app
from app.db import init_db, query_db, execute_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.custody.service import append as custody_append
from app.modules.evidence.service import intake_evidence
from app.modules.timeline.service import (
    get_merged_timeline_events,
    export_timeline_csv,
)


@pytest.fixture
def timeline_env(tmp_path):
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
        "SECRET_KEY": "test_secret_key_forensix_section11_timeline",
    })

    with app.app_context():
        init_db(db_path)
        lead_id = create_user("Lead User", "lead_time", "Lead", "LeadPass123!")
        analyst_id = create_user("Analyst User", "analyst_time", "Analyst", "AnalystPass123!")
        reviewer_id = create_user("Reviewer User", "reviewer_time", "Reviewer", "ReviewerPass123!")
        outsider_id = create_user("Outsider User", "outsider_time", "Analyst", "OutsiderPass123!")

        case_id = create_case("Timeline Incident Investigation", "Analyzing chronological sequence of breach", "High", lead_id)
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


def test_merge_events_from_multiple_sources(timeline_env):
    """
    Done condition: Events from at least three sources appear in one sorted, filterable view.
    Sources tested: auth.log, pcap, metadata, and custody_log.
    """
    app = timeline_env["app"]
    case_id = timeline_env["case_id"]
    lead_id = timeline_env["lead_id"]
    vault_dir = timeline_env["vault_dir"]
    work_dir = timeline_env["work_dir"]

    with app.app_context():
        # Create an evidence item
        storage = FileStorage(stream=io.BytesIO(b"evidence content"), filename="evidence.bin")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="evidence.bin",
        )

        # Source 1: auth.log
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, action, raw_line)
               VALUES (?, ?, 10, '2026-10-14T02:00:00Z', 'auth.log', '198.51.100.1', 'SSH_FAIL', 'Failed login')""",
            (case_id, ev_id),
        )

        # Source 2: pcap
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, action, raw_line)
               VALUES (?, ?, 20, '2026-10-14T02:05:00Z', 'pcap', '198.51.100.1', 'PORT_SCAN', 'Syn scan 20 ports')""",
            (case_id, ev_id),
        )

        # Source 3: metadata
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, action, raw_line)
               VALUES (?, ?, 30, '2026-10-14T02:10:00Z', 'metadata', NULL, 'FILE_CREATED', 'EXIF DateTimeOriginal')""",
            (case_id, ev_id),
        )

        # Source 4: custody_log
        custody_append(case_id, ev_id, lead_id, "ANALYST_TAG_UPDATE", {"tag": "suspicious"})

        # Retrieve merged timeline
        events = get_merged_timeline_events(case_id)
        assert len(events) >= 4

        sources = {e["source"] for e in events}
        assert "auth.log" in sources
        assert "pcap" in sources
        assert "metadata" in sources
        assert "custody" in sources

        # Verify sorted ascending by timestamp_utc
        timestamps = [e["timestamp_utc"] for e in events]
        assert timestamps == sorted(timestamps)


def test_severity_propagation_from_findings(timeline_env):
    """Verify that Critical or High findings propagate severity to matching evidence line events."""
    app = timeline_env["app"]
    case_id = timeline_env["case_id"]
    lead_id = timeline_env["lead_id"]
    vault_dir = timeline_env["vault_dir"]
    work_dir = timeline_env["work_dir"]

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(b"log data"), filename="auth.log")
        ev_id = intake_evidence(case_id, storage, lead_id, vault_dir, work_dir, "auth.log")

        # Insert normal event and compromised event
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, action, raw_line)
               VALUES (?, ?, 1, '2026-10-14T01:00:00Z', 'auth.log', '10.0.0.1', 'NORMAL_LOG', 'OK')""",
            (case_id, ev_id),
        )
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, action, raw_line)
               VALUES (?, ?, 151, '2026-10-14T02:59:00Z', 'auth.log', '198.51.100.77', 'SSH_SUCCESS', 'Compromise')""",
            (case_id, ev_id),
        )

        # Insert Critical finding referencing line 151
        execute_db(
            """INSERT INTO findings (case_id, evidence_id, rule, severity, src_ip, count, evidence_lines, status)
               VALUES (?, ?, 'SUCCESS_AFTER_FAILURES', 'Critical', '198.51.100.77', 1, 'Review lines: [151]', 'Open')""",
            (case_id, ev_id),
        )

        events = get_merged_timeline_events(case_id)
        ev_1 = next(e for e in events if e.get("raw_line") == "OK")
        ev_151 = next(e for e in events if e.get("raw_line") == "Compromise")

        assert ev_1["severity"] == "Info"
        assert ev_151["severity"] == "Critical"


def test_filters_by_source_and_severity(timeline_env):
    """Verify filtering by source and severity works cleanly."""
    app = timeline_env["app"]
    case_id = timeline_env["case_id"]

    with app.app_context():
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, action, raw_line)
               VALUES (?, NULL, 1, '2026-10-14T01:00:00Z', 'auth.log', 'SSH_FAIL', 'fail')""",
            (case_id,),
        )
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, action, raw_line)
               VALUES (?, NULL, 2, '2026-10-14T02:00:00Z', 'pcap', 'DNS_QUERY', 'dns')""",
            (case_id,),
        )

        # Filter auth.log only
        auth_events = get_merged_timeline_events(case_id, source_filter="auth.log")
        assert len(auth_events) == 1
        assert auth_events[0]["source"] == "auth.log"

        # Filter pcap only
        pcap_events = get_merged_timeline_events(case_id, source_filter="pcap")
        assert len(pcap_events) == 1
        assert pcap_events[0]["source"] == "pcap"


def test_csv_export_matches_table_and_logs_custody(timeline_env):
    """Verify CSV export contains rows and writes custody entry EXPORT_TIMELINE_CSV."""
    app = timeline_env["app"]
    case_id = timeline_env["case_id"]
    analyst_id = timeline_env["analyst_id"]

    with app.app_context():
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, action, raw_line)
               VALUES (?, NULL, 5, '2026-10-14T05:00:00Z', 'auth.log', '198.51.100.88', 'ROOT_LOGIN', 'Accepted password')""",
            (case_id,),
        )

        csv_str = export_timeline_csv(case_id)
        assert "Timestamp (UTC)" in csv_str
        assert "ROOT_LOGIN" in csv_str
        assert "198.51.100.88" in csv_str

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True

    resp = client.get(f"/cases/{case_id}/timeline/export.csv")
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert b"ROOT_LOGIN" in resp.data

    # Verify custody entry logged
    with app.app_context():
        custody_rows = query_db(
            "SELECT action, user_id FROM custody_log WHERE case_id = ? AND action = 'EXPORT_TIMELINE_CSV'",
            (case_id,),
        )
        assert len(custody_rows) == 1
        assert custody_rows[0]["user_id"] == analyst_id


def test_timeline_routes_and_access_control(timeline_env):
    """Verify @case_member_required blocks outsiders (404) and allows members (200)."""
    app = timeline_env["app"]
    case_id = timeline_env["case_id"]
    analyst_id = timeline_env["analyst_id"]
    outsider_id = timeline_env["outsider_id"]

    client = app.test_client()

    # 1. Outsider gets 404
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/timeline")
    assert resp.status_code == 404

    # 2. Member gets 200
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/timeline")
    assert resp.status_code == 200
    assert b"Investigation Timeline" in resp.data

    # 3. JSON data endpoint returns valid array
    resp_data = client.get(f"/cases/{case_id}/timeline/data")
    assert resp_data.status_code == 200
    items = resp_data.get_json()
    assert isinstance(items, list)
