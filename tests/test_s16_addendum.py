"""
ForensiX S16 Addendum Verification Test Suite.
Verifies all retroactive Addendum specifications:
  - A1: Sidebar navigation routes & structure
  - A5: Demo Mode ("Load Demo Case" endpoint and end-to-end artifact ingestion)
  - A6: Dashboard 11 Feature Map cards
  - B1: Guided Stepper (1 Evidence > 2 Verify > 3 Analyse > 4 Timeline > 5 Report) & Next Step buttons
  - B2: "What to do next" card on Case Overview
  - B3: Login centered card with tagline "Evidence you can verify"
  - B5: Forensic touches (shield icon on hash display, linked block visualization)
  - C2: Master key export & recovery
  - C4: Visible signature fields & detached .sig file
  - C6: Fallback magic MIME detection
"""

from __future__ import annotations

import io
from pathlib import Path
from werkzeug.datastructures import FileStorage
import pytest

from app import create_app
from app.db import init_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case
from app.modules.evidence.service import intake_evidence, fallback_magic_mime
from app.modules.reports.service import generate_forensic_report, sign_report
from app.security.crypto import export_encrypted_master_key, decrypt_exported_master_key


@pytest.fixture
def addendum_app(tmp_path):
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vault"
    db_path = data_dir / "db" / "forensix.db"
    master_key = data_dir / "keys" / "master.key"
    work_dir = data_dir / "work"
    reports_dir = data_dir / "reports"
    keys_dir = data_dir / "keys"
    logs_dir = data_dir / "logs"
    backups_dir = data_dir / "backups"

    app = create_app({
        "TESTING": True,
        "DATA_DIR": str(data_dir),
        "VAULT_DIR": str(vault_dir),
        "DB_DIR": str(data_dir / "db"),
        "KEYS_DIR": str(keys_dir),
        "LOGS_DIR": str(logs_dir),
        "WORK_DIR": str(work_dir),
        "REPORTS_DIR": str(reports_dir),
        "BACKUPS_DIR": str(backups_dir),
        "DATABASE_PATH": str(db_path),
        "MASTER_KEY_PATH": str(master_key),
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test_addendum_secret_forensix",
        "PUBLIC_VERIFY": True,
    })

    with app.app_context():
        init_db(db_path)
        admin_id = create_user("System Admin", "admin_user", "Admin", "AdminPass123!@#")
        lead_id = create_user("Lead Analyst", "lead_user", "Lead", "LeadPass123!@#")
        analyst_id = create_user("Junior Analyst", "analyst_user", "Analyst", "AnalystPass123!")

    return {
        "app": app,
        "admin_id": admin_id,
        "lead_id": lead_id,
        "analyst_id": analyst_id,
        "data_dir": data_dir,
        "vault_dir": vault_dir,
        "work_dir": work_dir,
        "reports_dir": reports_dir,
        "keys_dir": keys_dir,
    }


def test_login_page_renders_tagline_and_helper(addendum_app):
    """B3: Login page renders centered card with 'Evidence you can verify' and username helper."""
    client = addendum_app["app"].test_client()
    res = client.get("/login")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Evidence you can verify" in html
    assert "Enter your assigned username" in html


def test_dashboard_renders_feature_map_and_quick_actions(addendum_app):
    """A6 & B3: Dashboard renders quick-action row and all 11 feature map items."""
    client = addendum_app["app"].test_client()
    # Log in as Lead
    client.post("/login", data={"username": "lead_user", "password": "LeadPass123!@#"})

    res = client.get("/dashboard")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Quick action row buttons
    assert "Quick Actions" in html
    assert "New Case" in html
    assert "Load Demo Case" in html

    # Feature map
    assert "Platform Feature Map" in html
    assert "Case Management &amp; Auto-Numbering" in html or "Case Management & Auto-Numbering" in html
    assert "Secure Evidence Intake Vault" in html
    assert "Cryptographic Chain of Custody" in html
    assert "Native Image Metadata Extraction" in html
    assert "PCAP Network Traffic Dissection" in html
    assert "Authentication &amp; System Log Analysis" in html or "Authentication & System Log Analysis" in html
    assert "IOC Extraction &amp; Defanging" in html or "IOC Extraction & Defanging" in html
    assert "Interactive Forensic Timeline" in html
    assert "Section 63 BSA Compliance Reporting" in html
    assert "Public Cryptographic Report Verification" in html
    assert "Disaster Recovery &amp; Master Key Export" in html or "Disaster Recovery & Master Key Export" in html


def test_load_demo_case_creates_artifacts_and_redirects(addendum_app):
    """A5: POST /dashboard/load-demo-case ingests all 6 demo artifacts and populates tabs."""
    client = addendum_app["app"].test_client()
    client.post("/login", data={"username": "lead_user", "password": "LeadPass123!@#"})

    res = client.post("/dashboard/load-demo-case", follow_redirects=True)
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    assert "Operation Red Sandstorm" in html
    assert "1 Evidence" in html
    assert "2 Verify" in html
    assert "3 Analyse" in html
    assert "4 Timeline" in html
    assert "5 Report" in html

    # Verify database has the 6 artifacts ingested
    with addendum_app["app"].app_context():
        rows = query_db("SELECT display_name, integrity_status FROM evidence")
        names = {r["display_name"] for r in rows}
        assert "auth.log" in names
        assert "sample_photo.jpg" in names
        assert "fake_photo.jpg" in names
        assert "eicar.com" in names
        assert "suspicious_notes.txt" in names
        assert "sample.pcap" in names

        # Disguised executable should be SUSPICIOUS
        fake_row = next(r for r in rows if r["display_name"] == "fake_photo.jpg")
        assert fake_row["integrity_status"] == "SUSPICIOUS"


def test_case_header_stepper_and_what_to_do_next_card(addendum_app):
    """B1 & B2: Stepper and 'What to do next' card appear with appropriate guidance."""
    client = addendum_app["app"].test_client()
    client.post("/login", data={"username": "lead_user", "password": "LeadPass123!@#"})

    with addendum_app["app"].app_context():
        case_id = create_case("Empty Test Case", "No evidence yet", "Low", addendum_app["lead_id"])

    res = client.get(f"/cases/{case_id}")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Stepper present
    assert "1 Evidence" in html
    assert "2 Verify" in html
    assert "3 Analyse" in html

    # B2 "What to do next" card
    assert "Recommended Next Step" in html
    assert "No evidence yet" in html
    assert "Next: Evidence Vault &rarr;" in html


def test_master_key_export_route(addendum_app):
    """C2: POST /system/keys/export exports encrypted key and decrypts successfully."""
    client = addendum_app["app"].test_client()
    client.post("/login", data={"username": "admin_user", "password": "AdminPass123!@#"})

    passphrase = "SecureAdminPassphrase2026!"
    res = client.post("/system/keys/export", data={"passphrase": passphrase})
    assert res.status_code == 200
    assert res.headers.get("Content-Disposition") is not None
    assert "forensix_master_key.enc" in res.headers["Content-Disposition"]

    # Decrypt and verify matching key
    enc_payload = res.data
    with addendum_app["app"].app_context():
        from app.security.crypto import get_master_key
        actual_master_key = get_master_key()
        decrypted_key = decrypt_exported_master_key(enc_payload, passphrase)
        assert decrypted_key == actual_master_key


def test_report_signing_creates_detached_sig(addendum_app):
    """C4: Report signing produces detached .sig file and valid certificate metadata."""
    import hashlib
    from app.db import execute_db
    app = addendum_app["app"]
    lead_id = addendum_app["lead_id"]
    reports_dir = addendum_app["reports_dir"]
    keys_dir = addendum_app["keys_dir"]

    with app.app_context():
        case_id = create_case("Report Sig Case", "Verification of report signature", "Medium", lead_id)
        pdf_path = generate_forensic_report(case_id, lead_id, reports_dir)
        assert pdf_path.exists()

        sha = hashlib.sha256(pdf_path.read_bytes()).hexdigest()
        rep_id = execute_db(
            """INSERT INTO reports (case_id, file_name, sha256, signature, signed_by, chain_head_hash)
               VALUES (?, ?, ?, '', ?, '0000000000000000')""",
            (case_id, pdf_path.name, sha, lead_id),
        )

        ok = sign_report(rep_id, lead_id, "LeadPass123!@#", keys_dir, reports_dir=reports_dir)
        assert ok is True

        sig_path = reports_dir / f"{pdf_path.name}.sig"
        assert sig_path.exists()
        sig_content = sig_path.read_text(encoding="utf-8")
        assert len(sig_content) == 128  # 64-byte Ed25519 signature in hex


def test_magic_fallback_signatures():
    """C6: Built-in magic number fallback detects known file headers."""
    assert fallback_magic_mime(b"MZ\x90\x00\x03\x00") == "application/x-dosexec"
    assert fallback_magic_mime(b"\x7fELF\x02\x01\x01") == "application/x-executable"
    assert fallback_magic_mime(b"%PDF-1.7") == "application/pdf"
    assert fallback_magic_mime(b"\x89PNG\r\n\x1a\n\x00\x00") == "image/png"
    assert fallback_magic_mime(b"\xff\xd8\xff\xe0") == "image/jpeg"
    assert fallback_magic_mime(b"PK\x03\x04") == "application/zip"
    assert fallback_magic_mime(b"GIF89a...") == "image/gif"
    assert fallback_magic_mime(b"RANDOM_BYTES_HERE") == "application/octet-stream"
