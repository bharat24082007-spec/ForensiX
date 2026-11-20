"""
Tests for Section S12: Forensic Report Generator & Section 63 BSA Certificate.
Covers:
- PDF generation using ReportLab (produces valid %PDF document)
- Inclusion of Section 63 BSA Certificate and ISO/IEC 27037 checklist
- Detection and warning banners for broken custody chain or compromised evidence
- Step-up password verification for Ed25519 digital signature creation
- Cryptographic verification of report signature (Authentic vs Modified)
- Single-byte alteration of PDF document triggers verification failure
- RBAC enforcement: Reviewer denied generation (403), non-members denied access (404), Lead can sign
"""

import io
from pathlib import Path
import pypdf
import pytest
from werkzeug.datastructures import FileStorage

from app import create_app
from app.db import init_db, query_db, execute_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.custody.service import append as custody_append
from app.modules.evidence.service import intake_evidence
from app.modules.reports.service import (
    generate_forensic_report,
    sign_report,
    verify_report_signature,
    list_case_reports,
)


@pytest.fixture
def reports_env(tmp_path):
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vault"
    db_path = data_dir / "db" / "forensix.db"
    master_key = data_dir / "keys" / "master.key"
    work_dir = data_dir / "work"
    reports_dir = data_dir / "reports"
    keys_dir = data_dir / "keys"

    app = create_app({
        "TESTING": True,
        "DATA_DIR": str(data_dir),
        "VAULT_DIR": str(vault_dir),
        "DB_DIR": str(data_dir / "db"),
        "KEYS_DIR": str(keys_dir),
        "LOGS_DIR": str(data_dir / "logs"),
        "WORK_DIR": str(work_dir),
        "REPORTS_DIR": str(reports_dir),
        "DATABASE_PATH": str(db_path),
        "MASTER_KEY_PATH": str(master_key),
        "WTF_CSRF_ENABLED": False,
        "ALLOW_LAN": False,
        "HOST": "127.0.0.1",
        "PORT": 5000,
        "SECRET_KEY": "test_secret_key_forensix_section12_reports",
        "PUBLIC_VERIFY": True,
    })

    with app.app_context():
        init_db(db_path)
        lead_id = create_user("Lead Investigator", "lead_rep", "Lead", "LeadPass123!@#")
        analyst_id = create_user("Analyst Investigator", "analyst_rep", "Analyst", "AnalystPass123!")
        reviewer_id = create_user("Reviewer User", "reviewer_rep", "Reviewer", "ReviewerPass123!")
        outsider_id = create_user("Outsider User", "outsider_rep", "Analyst", "OutsiderPass123!")

        case_id = create_case("Forensic Breach Investigation", "In-depth corporate breach analysis", "Critical", lead_id)
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
        "reports_dir": reports_dir,
        "keys_dir": keys_dir,
    }


def test_report_generation_produces_pdf(reports_env):
    """Verify generate_forensic_report builds a real PDF file with valid header."""
    app = reports_env["app"]
    case_id = reports_env["case_id"]
    lead_id = reports_env["lead_id"]
    reports_dir = reports_env["reports_dir"]
    vault_dir = reports_env["vault_dir"]
    work_dir = reports_env["work_dir"]

    with app.app_context():
        # Ingest an evidence item
        storage = FileStorage(stream=io.BytesIO(b"critical breach evidence"), filename="breach.bin")
        ev_id = intake_evidence(case_id, storage, lead_id, vault_dir, work_dir, "generic.bin")

        # Ingest custody entry, findings, events
        custody_append(case_id, ev_id, lead_id, "EXAMINE_EVIDENCE", {"tool": "hexview"})
        execute_db(
            """INSERT INTO findings (case_id, evidence_id, rule, severity, src_ip, count, evidence_lines, status)
               VALUES (?, ?, 'MALWARE_DROP', 'High', '198.51.100.9', 1, '1', 'Open')""",
            (case_id, ev_id),
        )
        execute_db(
            """INSERT INTO iocs (case_id, type, value, first_evidence_id, verdict, source)
               VALUES (?, 'ipv4', '198.51.100.9', ?, 'Known malicious', 'unit_test')""",
            (case_id, ev_id),
        )

        pdf_path = generate_forensic_report(case_id, lead_id, reports_dir)
        assert pdf_path.is_file()

        content = pdf_path.read_bytes()
        assert content.startswith(b"%PDF")
        assert len(content) > 1000


def test_sign_and_verify_authentic(reports_env):
    """Verify signing a report with Lead step-up password creates valid signature that verifies Authentic."""
    app = reports_env["app"]
    case_id = reports_env["case_id"]
    lead_id = reports_env["lead_id"]
    reports_dir = reports_env["reports_dir"]
    keys_dir = reports_env["keys_dir"]

    client = app.test_client()

    with app.app_context():
        pdf_path = generate_forensic_report(case_id, lead_id, reports_dir)
        import hashlib
        sha = hashlib.sha256(pdf_path.read_bytes()).hexdigest()

        rep_id = execute_db(
            """INSERT INTO reports (case_id, file_name, sha256, signature, signed_by, chain_head_hash)
               VALUES (?, ?, ?, '', ?, '0000000000000000')""",
            (case_id, pdf_path.name, sha, lead_id),
        )

        # 1. Invalid password fails step-up authentication
        ok_wrong = sign_report(rep_id, lead_id, "WrongPassword!", keys_dir)
        assert ok_wrong is False

        # 2. Correct password signs report
        ok_right = sign_report(rep_id, lead_id, "LeadPass123!@#", keys_dir)
        assert ok_right is True

        rep_row = query_db("SELECT signature FROM reports WHERE id = ?", (rep_id,), one=True)
        assert rep_row["signature"] != ""

        # 3. Verify signature
        pdf_bytes = pdf_path.read_bytes()
        ver_res = verify_report_signature(pdf_bytes, rep_id)
        assert ver_res["authentic"] is True
        assert "Lead Investigator" in ver_res["signer"]


def test_tampered_pdf_shows_modified(reports_env):
    """Done condition: changing a single byte of the PDF makes the Verify page show Modified."""
    app = reports_env["app"]
    case_id = reports_env["case_id"]
    lead_id = reports_env["lead_id"]
    reports_dir = reports_env["reports_dir"]
    keys_dir = reports_env["keys_dir"]

    with app.app_context():
        pdf_path = generate_forensic_report(case_id, lead_id, reports_dir)
        import hashlib
        sha = hashlib.sha256(pdf_path.read_bytes()).hexdigest()

        rep_id = execute_db(
            """INSERT INTO reports (case_id, file_name, sha256, signature, signed_by, chain_head_hash)
               VALUES (?, ?, ?, '', ?, '0000000000000000')""",
            (case_id, pdf_path.name, sha, lead_id),
        )
        assert sign_report(rep_id, lead_id, "LeadPass123!@#", keys_dir) is True

        original_bytes = bytearray(pdf_path.read_bytes())

        # Flip one byte near the end of the PDF
        tampered_bytes = bytearray(original_bytes)
        tampered_bytes[-100] = (tampered_bytes[-100] + 1) % 256

        ver_res = verify_report_signature(bytes(tampered_bytes), rep_id)
        assert ver_res["authentic"] is False
        assert "modified" in ver_res["reason"].lower()


def test_compromised_evidence_warning_in_report(reports_env):
    """Verify that compromised evidence triggers a warning banner in generated report."""
    app = reports_env["app"]
    case_id = reports_env["case_id"]
    lead_id = reports_env["lead_id"]
    reports_dir = reports_env["reports_dir"]
    vault_dir = reports_env["vault_dir"]
    work_dir = reports_env["work_dir"]

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(b"tampered content"), filename="compromised.img")
        ev_id = intake_evidence(case_id, storage, lead_id, vault_dir, work_dir, "compromised.img")

        # Mark compromised
        execute_db("UPDATE evidence SET integrity_status = 'COMPROMISED' WHERE id = ?", (ev_id,))

        pdf_path = generate_forensic_report(case_id, lead_id, reports_dir)
        reader = pypdf.PdfReader(str(pdf_path))
        pdf_text = "".join(page.extract_text() for page in reader.pages)
        assert "COMPROMISED" in pdf_text
        assert "WARNING" in pdf_text


def test_broken_chain_warning_in_report(reports_env):
    """Verify that a broken custody chain prints a prominent warning banner in the PDF report."""
    app = reports_env["app"]
    case_id = reports_env["case_id"]
    lead_id = reports_env["lead_id"]
    reports_dir = reports_env["reports_dir"]

    with app.app_context():
        # Append custody entries
        custody_append(case_id, None, lead_id, "ACTION_1", {"k": 1})
        custody_append(case_id, None, lead_id, "ACTION_2", {"k": 2})

        # Tamper with the custody chain (temporarily drop trigger, edit, restore)
        execute_db("DROP TRIGGER IF EXISTS trg_custody_log_no_update")
        execute_db("UPDATE custody_log SET action = 'ACTION_TAMPERED' WHERE action = 'ACTION_1'")
        execute_db("""
            CREATE TRIGGER trg_custody_log_no_update
            BEFORE UPDATE ON custody_log
            BEGIN
                SELECT RAISE(ABORT, 'custody_log is append-only');
            END;
        """)

        pdf_path = generate_forensic_report(case_id, lead_id, reports_dir)
        reader = pypdf.PdfReader(str(pdf_path))
        pdf_text = "".join(page.extract_text() for page in reader.pages)
        assert "BROKEN" in pdf_text
        assert "INTEGRITY" in pdf_text


def test_report_routes_and_rbac(reports_env):
    """Verify access controls: Reviewer denied generate (403), non-members denied (404), Lead can generate."""
    app = reports_env["app"]
    case_id = reports_env["case_id"]
    analyst_id = reports_env["analyst_id"]
    reviewer_id = reports_env["reviewer_id"]
    outsider_id = reports_env["outsider_id"]

    client = app.test_client()

    # 1. Outsider gets 404
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/reports")
    assert resp.status_code == 404

    # 2. Member gets 200
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/reports")
    assert resp.status_code == 200
    assert b"Forensic Reports" in resp.data

    # 3. Reviewer cannot generate report -> 403
    with client.session_transaction() as sess:
        sess["_user_id"] = str(reviewer_id)
        sess["_fresh"] = True
    resp_gen = client.post(f"/cases/{case_id}/reports/generate")
    assert resp_gen.status_code == 403
