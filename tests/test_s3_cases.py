"""
Tests for Section S3: Case Management.
Verifies case creation with automated sequential identifiers (CASE-YYYY-XXXX),
per-case membership enforcement (Analyst sees only assigned cases, Admin has no access without membership),
member assignment and removal, status transitions, and Legal Hold safeguards.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from datetime import datetime, timezone

from app import create_app
from app.db import execute_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import (
    generate_next_case_no,
    create_case,
    list_cases_for_user,
    get_case_details,
    assign_member,
    remove_member,
    update_case_status,
    toggle_legal_hold,
    get_case_overview_summary,
)


@pytest.fixture
def case_app(tmp_path: Path):
    """Fixture providing a test application with an isolated database."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    data_dir = tmp_path / "data"

    app = create_app(
        test_config={
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,  # Disabled for unit testing HTTP routes
            "SECRET_KEY": valid_key,
            "HOST": "127.0.0.1",
            "PORT": 5000,
            "ALLOW_LAN": False,
            "DATA_DIR": str(data_dir),
            "DATABASE_PATH": str(data_dir / "db" / "forensix.sqlite"),
        }
    )
    yield app


def test_auto_numbering_and_case_creation(case_app):
    """Verify sequential case numbering (CASE-YYYY-XXXX) and initial custody logging."""
    with case_app.app_context():
        lead_id = create_user("Sarah Lead", "slead", "Lead", "LeadPass12345!")

        # 1. Create first case
        case_id_1 = create_case("Incident Alpha", "Initial triage", "High", lead_id)
        case_1 = get_case_details(case_id_1)
        current_year = datetime.now(timezone.utc).year
        assert case_1["case_no"] == f"CASE-{current_year}-0001"
        assert case_1["status"] == "Open"
        assert case_1["priority"] == "High"
        assert case_1["legal_hold"] == 0

        # Verify lead was automatically added as a member
        members_1 = query_db("SELECT user_id FROM case_members WHERE case_id = ?", (case_id_1,))
        member_ids_1 = [m["user_id"] for m in members_1]
        assert lead_id in member_ids_1

        # 2. Create second case
        case_id_2 = create_case("Incident Beta", "Secondary triage", "Medium", lead_id)
        case_2 = get_case_details(case_id_2)
        assert case_2["case_no"] == f"CASE-{current_year}-0002"

        # Verify custody entry was written
        custody_rows = query_db("SELECT action FROM custody_log WHERE case_id = ?", (case_id_1,))
        actions = [r["action"] for r in custody_rows]
        assert "CASE_CREATED" in actions


def test_analyst_cannot_create_case(case_app):
    """Verify non-Lead roles (Analyst) are blocked from hitting /cases/new (HTTP 403)."""
    with case_app.app_context():
        analyst_id = create_user("Dan Analyst", "danalyst", "Analyst", "AnalystPass123!")

    client = case_app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True

    resp_get = client.get("/cases/new")
    assert resp_get.status_code == 403

    resp_post = client.post("/cases/new", data={"title": "Illegal Case", "priority": "Low"})
    assert resp_post.status_code == 403


def test_analyst_only_sees_assigned_cases_and_admin_sees_none(case_app):
    """
    Verify strict separation of duties and per-case access control:
    - Analyst sees ONLY cases to which they are assigned.
    - Admin sees NO cases in list or detail unless assigned as a member.
    """
    with case_app.app_context():
        lead_id = create_user("Lead User", "lead_user", "Lead", "Pass123456789!")
        analyst_id = create_user("Analyst User", "analyst_user", "Analyst", "Pass123456789!")
        admin_id = create_user("Admin User", "admin_user", "Admin", "Pass123456789!")

        # Create two cases
        case1_id = create_case("Network Intrusion", "Compromised DMZ", "Critical", lead_id)
        case2_id = create_case("Ransomware Payload", "Encrypted NAS", "High", lead_id)

        # Assign Analyst to Case 1 ONLY
        assign_member(case1_id, analyst_id, lead_id)

    client = case_app.test_client()

    # 1. Analyst test
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True

    # Analyst listing
    analyst_list = client.get("/cases")
    assert analyst_list.status_code == 200
    html_analyst = analyst_list.data.decode("utf-8")
    assert "Network Intrusion" in html_analyst
    assert "Ransomware Payload" not in html_analyst

    # Analyst accessing Case 1 -> 200
    c1_resp = client.get(f"/cases/{case1_id}")
    assert c1_resp.status_code == 200

    # Analyst accessing Case 2 -> 404 (Not Found, prevents enumeration)
    c2_resp = client.get(f"/cases/{case2_id}")
    assert c2_resp.status_code == 404

    # 2. Admin test (Separation of duties)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)
        sess["_fresh"] = True

    # Admin listing should show 0 cases
    admin_list = client.get("/cases")
    assert admin_list.status_code == 200
    html_admin = admin_list.data.decode("utf-8")
    assert "No Cases Found" in html_admin

    # Admin accessing Case 1 -> 404 (Separation of duties)
    admin_c1 = client.get(f"/cases/{case1_id}")
    assert admin_c1.status_code == 404


def test_member_assignment_and_removal(case_app):
    """Verify Lead can add and remove members, but cannot remove the Lead."""
    with case_app.app_context():
        lead_id = create_user("Lead 2", "lead2", "Lead", "Pass123456789!")
        analyst_id = create_user("Analyst 2", "analyst2", "Analyst", "Pass123456789!")
        case_id = create_case("APT Investigation", "Tracing malware", "Medium", lead_id)

    client = case_app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)
        sess["_fresh"] = True

    # Assign analyst
    add_resp = client.post(
        f"/cases/{case_id}/members/add",
        data={"user_id": analyst_id},
        follow_redirects=True,
    )
    assert add_resp.status_code == 200
    assert b"Member assigned to case successfully" in add_resp.data

    # Verify membership
    with case_app.app_context():
        check_member = query_db(
            "SELECT 1 FROM case_members WHERE case_id = ? AND user_id = ?",
            (case_id, analyst_id),
            one=True,
        )
        assert check_member is not None

    # Remove analyst
    rem_resp = client.post(
        f"/cases/{case_id}/members/remove",
        data={"user_id": analyst_id},
        follow_redirects=True,
    )
    assert rem_resp.status_code == 200
    assert b"Member removed from case" in rem_resp.data

    # Verify removal
    with case_app.app_context():
        check_removed = query_db(
            "SELECT 1 FROM case_members WHERE case_id = ? AND user_id = ?",
            (case_id, analyst_id),
            one=True,
        )
        assert check_removed is None

    # Attempt to remove Lead must fail
    rem_lead = client.post(
        f"/cases/{case_id}/members/remove",
        data={"user_id": lead_id},
        follow_redirects=True,
    )
    assert b"Cannot remove the case lead" in rem_lead.data


def test_status_transitions_and_closing(case_app):
    """Verify case status flow (Open -> In Progress -> Under Review -> Closed)."""
    with case_app.app_context():
        lead_id = create_user("Lead 3", "lead3", "Lead", "Pass123456789!")
        analyst_id = create_user("Analyst 3", "analyst3", "Analyst", "Pass123456789!")
        case_id = create_case("Phishing Campaign", "CEO Fraud", "Medium", lead_id)
        assign_member(case_id, analyst_id, lead_id)

    client = case_app.test_client()

    # Lead updates to In Progress
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)
        sess["_fresh"] = True

    resp_progress = client.post(
        f"/cases/{case_id}/status",
        data={"status": "In Progress"},
        follow_redirects=True,
    )
    assert resp_progress.status_code == 200
    assert b"Case status updated to In Progress" in resp_progress.data

    # Non-lead cannot close case
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True

    resp_analyst_close = client.post(
        f"/cases/{case_id}/status",
        data={"status": "Closed"},
        follow_redirects=True,
    )
    assert b"Only the case lead can close a case" in resp_analyst_close.data

    # Lead closes case
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)
        sess["_fresh"] = True

    resp_lead_close = client.post(
        f"/cases/{case_id}/status",
        data={"status": "Closed"},
        follow_redirects=True,
    )
    assert resp_lead_close.status_code == 200
    assert b"Case status updated to Closed" in resp_lead_close.data

    with case_app.app_context():
        case = get_case_details(case_id)
        assert case["status"] == "Closed"
        assert case["closed_at"] is not None


def test_legal_hold_blocks_closing_and_writes_custody_entries(case_app):
    """
    Verify Legal Hold:
    - While active, case status change to Closed is strictly blocked.
    - Toggling Legal Hold records custody entries.
    """
    with case_app.app_context():
        lead_id = create_user("Lead 4", "lead4", "Lead", "Pass123456789!")
        case_id = create_case("Insider Exfiltration", "Trade secrets leak", "Critical", lead_id)

    client = case_app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)
        sess["_fresh"] = True

    # 1. Enable Legal Hold
    resp_enable = client.post(f"/cases/{case_id}/legal-hold", follow_redirects=True)
    assert resp_enable.status_code == 200
    assert b"LEGAL HOLD ACTIVE" in resp_enable.data

    with case_app.app_context():
        case = get_case_details(case_id)
        assert case["legal_hold"] == 1

    # 2. Attempt to close case while Legal Hold is ON -> MUST BE BLOCKED
    resp_close_blocked = client.post(
        f"/cases/{case_id}/status",
        data={"status": "Closed"},
        follow_redirects=True,
    )
    assert b"Case cannot be closed while Legal Hold is active" in resp_close_blocked.data

    with case_app.app_context():
        case = get_case_details(case_id)
        assert case["status"] != "Closed"

    # 3. Release Legal Hold
    resp_release = client.post(f"/cases/{case_id}/legal-hold", follow_redirects=True)
    assert resp_release.status_code == 200
    assert b"Legal Hold has been disabled" in resp_release.data

    with case_app.app_context():
        case = get_case_details(case_id)
        assert case["legal_hold"] == 0

    # 4. Now case can be closed
    resp_close_allowed = client.post(
        f"/cases/{case_id}/status",
        data={"status": "Closed"},
        follow_redirects=True,
    )
    assert b"Case status updated to Closed" in resp_close_allowed.data

    with case_app.app_context():
        # Verify custody audit events
        custody_rows = query_db("SELECT action FROM custody_log WHERE case_id = ?", (case_id,))
        actions = [r["action"] for r in custody_rows]
        assert "LEGAL_HOLD_ENABLED" in actions
        assert "LEGAL_HOLD_DISABLED" in actions
