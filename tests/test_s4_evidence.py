"""
Tests for Section S4: Evidence Vault.
Verifies streaming intake pipeline, SHA-256 fingerprinting,
AES-256-GCM chunked encryption at rest, path traversal neutralization,
MIME vs extension discrepancy detection, integrity-verified downloads,
and Legal-Hold-compliant evidence withdrawal.
"""

from __future__ import annotations

import io
import hashlib
from pathlib import Path
import pytest
from werkzeug.datastructures import FileStorage

from app import create_app
from app.db import execute_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, toggle_legal_hold
from app.modules.evidence.service import (
    sanitize_filename,
    detect_mime_and_suspicious_mismatch,
    intake_evidence,
    verify_and_decrypt_evidence,
    get_evidence_details,
    withdraw_evidence,
)


@pytest.fixture
def evidence_app(tmp_path: Path):
    """Fixture providing an isolated application instance and vault directory."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    data_dir = tmp_path / "data"

    app = create_app(
        test_config={
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": valid_key,
            "HOST": "127.0.0.1",
            "PORT": 5000,
            "ALLOW_LAN": False,
            "DATA_DIR": str(data_dir),
            "DATABASE_PATH": str(data_dir / "db" / "forensix.sqlite"),
        }
    )
    yield app


def test_filename_sanitization_neutralizes_traversal():
    """Verify path traversal vectors are thoroughly neutralized."""
    traversal_samples = [
        ("../../etc/shadow", "shadow"),
        ("..\\..\\windows\\system32\\cmd.exe", "cmd.exe"),
        ("/var/log/syslog", "syslog"),
        ("..\\..\\boot.ini\x00.jpg", "boot.ini.jpg"),
        ("../../../secret.docx", "secret.docx"),
        ("", "unnamed_evidence"),
    ]
    for vector, expected in traversal_samples:
        assert sanitize_filename(vector) == expected


def test_evidence_intake_and_sha256_fingerprint(evidence_app):
    """Verify upload pipeline hashes plaintext SHA-256 and encrypts into vault."""
    with evidence_app.app_context():
        lead_id = create_user("Lead Investigator", "lead_inv", "Lead", "Pass123456789!")
        case_id = create_case("Vault Test Case", "Testing evidence intake", "High", lead_id)

    client = evidence_app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)
        sess["_fresh"] = True

    sample_content = b"CRITICAL FORENSIC EVIDENCE: Encrypted payload dump 2026."
    expected_sha256 = hashlib.sha256(sample_content).hexdigest()

    # Upload file
    response = client.post(
        f"/cases/{case_id}/evidence/upload",
        data={
            "file": (io.BytesIO(sample_content), "network_dump.pcap"),
            "tags": "pcap, perimeter_firewall",
            "notes": "Acquired from core router interface gig0/1",
            "source_type": "pcap",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Verify SHA-256 is displayed in the UI
    assert expected_sha256 in html
    assert "network_dump.pcap" in html
    assert "VERIFIED" in html

    # Verify database record
    with evidence_app.app_context():
        ev_row = query_db(
            "SELECT * FROM evidence WHERE case_id = ? AND display_name = 'network_dump.pcap'",
            (case_id,),
            one=True,
        )
        assert ev_row is not None
        assert ev_row["sha256"] == expected_sha256
        assert ev_row["size"] == len(sample_content)
        assert ev_row["integrity_status"] == "VERIFIED"

        # Verify UPLOAD action logged in custody_log
        custody = query_db("SELECT action FROM custody_log WHERE evidence_id = ?", (ev_row["id"],), one=True)
        assert custody["action"] == "UPLOAD"


def test_vault_file_is_encrypted_and_unreadable_without_key(evidence_app):
    """Verify raw bytes on disk in data/vault/ DO NOT contain plaintext."""
    with evidence_app.app_context():
        lead_id = create_user("Lead 2", "lead2", "Lead", "Pass123456789!")
        case_id = create_case("Confidentiality Test", "Testing AES-GCM vault", "Medium", lead_id)

        secret_plaintext = b"CONFIDENTIAL_INVESTIGATION_KEY_MATERIAL_NEVER_LEAK_PLAINTEXT"
        vault_dir = Path(evidence_app.config["VAULT_DIR"])
        work_dir = Path(evidence_app.config["WORK_DIR"])

        storage = FileStorage(stream=io.BytesIO(secret_plaintext), filename="secret_keys.txt")
        evidence_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
        )

        ev_row = get_evidence_details(evidence_id)
        vault_file_path = vault_dir / ev_row["stored_name"]
        assert vault_file_path.is_file()

        # Read raw on-disk bytes
        with open(vault_file_path, "rb") as f:
            raw_vault_bytes = f.read()

        # Raw bytes must NOT contain secret plaintext
        assert secret_plaintext not in raw_vault_bytes
        # File header must start with magic FVAU
        assert raw_vault_bytes[:4] == b"FVAU"


def test_type_mismatch_flags_suspicious(evidence_app):
    """Verify fake extension (e.g. photo.jpg containing MZ executable) is flagged SUSPICIOUS."""
    with evidence_app.app_context():
        lead_id = create_user("Lead 3", "lead3", "Lead", "Pass123456789!")
        case_id = create_case("Malware Masking Case", "Detect fake extensions", "Critical", lead_id)

        # Fake JPG containing DOS MZ executable header
        fake_jpg_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00FakeMalwareExecutablePayload"
        vault_dir = Path(evidence_app.config["VAULT_DIR"])
        work_dir = Path(evidence_app.config["WORK_DIR"])

        storage = FileStorage(stream=io.BytesIO(fake_jpg_content), filename="innocent_family_photo.jpg")
        evidence_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
        )

        ev = get_evidence_details(evidence_id)
        # MUST BE FLAGGED AS SUSPICIOUS
        assert ev["integrity_status"] == "SUSPICIOUS"


def test_verified_download_and_tamper_detection(evidence_app):
    """
    Verify:
    1. Downloading intact evidence succeeds and matches original bytes.
    2. Modifying a byte in data/vault/<uuid>.enc trips integrity check and marks COMPROMISED.
    """
    with evidence_app.app_context():
        lead_id = create_user("Lead 4", "lead4", "Lead", "Pass123456789!")
        case_id = create_case("Integrity Verification Case", "Testing tamper detection", "High", lead_id)

        original_data = b"INTEGRITY_CHECK_SAMPLE_DATA_CHUNK_TEST"
        vault_dir = Path(evidence_app.config["VAULT_DIR"])
        work_dir = Path(evidence_app.config["WORK_DIR"])

        storage = FileStorage(stream=io.BytesIO(original_data), filename="contract.pdf")
        evidence_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
        )

        # 1. Download intact evidence
        data, name, mime = verify_and_decrypt_evidence(
            evidence_id=evidence_id,
            vault_dir=vault_dir,
            acting_user_id=lead_id,
            action="DOWNLOAD",
        )
        assert data == original_data
        assert name == "contract.pdf"

        # 2. Tamper with the vault file (flip a byte)
        ev = get_evidence_details(evidence_id)
        vault_file_path = vault_dir / ev["stored_name"]

        # Temporarily enable write permission to simulate external disk/file tampering
        import stat
        import os
        os.chmod(vault_file_path, stat.S_IWRITE)
        with open(vault_file_path, "r+b") as f:
            f.seek(20)  # Seek into ciphertext/nonce
            current_byte = f.read(1)
            f.seek(20)
            tampered_byte = bytes([(current_byte[0] ^ 0xFF)])
            f.write(tampered_byte)
        os.chmod(vault_file_path, stat.S_IREAD)

        # 3. Attempting to download tampered file must fail and mark COMPROMISED
        with pytest.raises(ValueError, match="integrity compromised"):
            verify_and_decrypt_evidence(
                evidence_id=evidence_id,
                vault_dir=vault_dir,
                acting_user_id=lead_id,
                action="DOWNLOAD",
            )

        # Verify status changed in database to COMPROMISED
        ev_after_tamper = get_evidence_details(evidence_id)
        assert ev_after_tamper["integrity_status"] == "COMPROMISED"

        # Verify VERIFY_FAIL action logged in custody log
        verify_fail_entry = query_db(
            "SELECT action FROM custody_log WHERE evidence_id = ? AND action = 'VERIFY_FAIL'",
            (evidence_id,),
            one=True,
        )
        assert verify_fail_entry is not None


def test_evidence_withdrawal_and_legal_hold_blocking(evidence_app):
    """
    Verify:
    1. Withdrawal requires formal reason and Lead role.
    2. Evidence cannot be withdrawn while Legal Hold is active.
    3. Withdrawn evidence is never deleted.
    """
    with evidence_app.app_context():
        lead_id = create_user("Lead 5", "lead5", "Lead", "Pass123456789!")
        analyst_id = create_user("Analyst 5", "analyst5", "Analyst", "Pass123456789!")
        case_id = create_case("Withdrawal Case", "Testing Legal Hold blocks", "Medium", lead_id)

        vault_dir = Path(evidence_app.config["VAULT_DIR"])
        work_dir = Path(evidence_app.config["WORK_DIR"])

        storage = FileStorage(stream=io.BytesIO(b"Data file"), filename="audit.log")
        eid = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
        )

        # Enable Legal Hold on case
        toggle_legal_hold(case_id, lead_id)

        # Attempt withdrawal while Legal Hold is ON -> MUST BE BLOCKED
        with pytest.raises(PermissionError, match="forbidden while Legal Hold is active"):
            withdraw_evidence(eid, "Test withdrawal", lead_id)

        # Release Legal Hold
        toggle_legal_hold(case_id, lead_id)

        # Non-lead cannot withdraw
        with pytest.raises(PermissionError, match="Only the case lead"):
            withdraw_evidence(eid, "Reason", analyst_id)

        # Missing reason raises ValueError
        with pytest.raises(ValueError, match="formal reason is strictly required"):
            withdraw_evidence(eid, "   ", lead_id)

        # Lead withdraws successfully
        withdraw_evidence(eid, "Artifact acquired outside scope of warrant", lead_id)

        ev_withdrawn = get_evidence_details(eid)
        assert ev_withdrawn["withdrawn"] == 1
        assert ev_withdrawn["withdrawn_reason"] == "Artifact acquired outside scope of warrant"

        # Vault file still exists on disk (evidence is never deleted)
        vault_file = vault_dir / ev_withdrawn["stored_name"]
        assert vault_file.is_file()
