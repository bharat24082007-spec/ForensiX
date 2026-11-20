"""
ForensiX S15 Test Suite: Demo Data, End-to-End Investigation Lifecycle & Script Scenarios.
Covers:
  - make_demo_data.py generation of all 6 offline forensic artifacts
  - Structural and cryptographic validity of generated demo artifacts
  - The Sleuth Kit (fls) adapter safety and parsing
  - Complete end-to-end investigation workflow (intake, metadata, log analysis, IOCs, signed reports)
  - Demo script tamper detection (broken custody entry, bit-flipped vault file, tampered report PDF)
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import struct
from pathlib import Path
from unittest.mock import patch
from werkzeug.datastructures import FileStorage

import pytest
from PIL import Image

from app import create_app
from app.db import init_db, query_db, execute_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.evidence.service import intake_evidence, get_evidence_details
from app.modules.custody.service import verify_chain
from app.modules.metadata.service import extract_native_image_metadata, analyze_evidence_metadata
from app.modules.logs.service import analyze_log_evidence
from app.modules.iocs.service import extract_and_store_iocs
from app.modules.network.service import parse_pcap_in_memory
from app.modules.reports.service import generate_forensic_report, sign_report, verify_report_signature
from app.modules.integrity.watchdog import run_integrity_watchdog_job
from app.adapters.sleuthkit import list_disk_image_files
from tools.make_demo_data import (
    generate_all_demo_data,
    EICAR_STRING,
)


@pytest.fixture
def demo_env(tmp_path):
    """Fixture providing a fresh ForensiX application environment for demo verification."""
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vault"
    db_path = data_dir / "db" / "forensix.db"
    master_key = data_dir / "keys" / "master.key"
    work_dir = data_dir / "work"
    reports_dir = data_dir / "reports"
    keys_dir = data_dir / "keys"
    logs_dir = data_dir / "logs"

    app = create_app({
        "TESTING": True,
        "DATA_DIR": str(data_dir),
        "VAULT_DIR": str(vault_dir),
        "DB_DIR": str(data_dir / "db"),
        "KEYS_DIR": str(keys_dir),
        "LOGS_DIR": str(logs_dir),
        "WORK_DIR": str(work_dir),
        "REPORTS_DIR": str(reports_dir),
        "DATABASE_PATH": str(db_path),
        "MASTER_KEY_PATH": str(master_key),
        "WTF_CSRF_ENABLED": False,
        "ALLOW_LAN": False,
        "HOST": "127.0.0.1",
        "PORT": 5000,
        "SECRET_KEY": "demo_test_secret_key_forensix_s15",
        "PUBLIC_VERIFY": True,
    })

    with app.app_context():
        init_db(db_path)
        lead_id = create_user("Lead Investigator", "lead_demo", "Lead", "LeadPass123!@#")
        analyst_id = create_user("Analyst Investigator", "analyst_demo", "Analyst", "AnalystPass123!")

        case_id = create_case("Operation Horizon Demo", "Investigating intrusion & data leak", "Critical", lead_id)
        assign_member(case_id, analyst_id, lead_id)

    return {
        "app": app,
        "lead_id": lead_id,
        "analyst_id": analyst_id,
        "case_id": case_id,
        "vault_dir": vault_dir,
        "work_dir": work_dir,
        "reports_dir": reports_dir,
        "keys_dir": keys_dir,
        "db_path": db_path,
    }


def test_make_demo_data_generates_all_files(tmp_path):
    """Verify make_demo_data produces all 6 expected forensic artifacts with correct formats and hashes."""
    demo_dir = tmp_path / "demo_output"
    files = generate_all_demo_data(demo_dir)

    assert len(files) == 6
    for key, path in files.items():
        if key == "eicar" and not path.exists():
            continue  # Host Defender / real-time AV may immediately quarantine raw EICAR
        assert path.exists(), f"File for {key} was not created"
        assert path.stat().st_size > 0, f"File for {key} is empty"

    # 1. auth.log
    auth_log = files["auth_log"]
    content = auth_log.read_text(encoding="utf-8")
    lines = content.splitlines()
    assert len(lines) >= 155
    assert "Failed password for invalid user root from 198.51.100.77" in content
    assert "Accepted password for root from 198.51.100.77" in content

    # 2. sample_photo.jpg (JPEG with EXIF and GPS)
    photo = files["sample_photo"]
    img = Image.open(photo)
    assert img.format == "JPEG"
    exif = img.getexif()
    assert exif.get(0x010F) == "Nikon"
    assert exif.get(0x0110) == "D850"
    gps = exif.get_ifd(0x8825)
    assert gps.get(1) == "N"
    assert gps.get(3) == "E"
    img.close()

    # Also verify through our metadata extraction service
    meta = extract_native_image_metadata(photo.read_bytes())
    assert meta["camera_make"] == "Nikon"
    assert meta["camera_model"] == "D850"
    assert meta["gps_latitude"] is not None
    assert abs(meta["gps_latitude"] - 28.614) < 0.001
    assert meta["gps_longitude"] is not None
    assert abs(meta["gps_longitude"] - 77.2089) < 0.001

    # 3. fake_photo.jpg (MZ DOS executable header)
    fake_photo = files["fake_photo"]
    data = fake_photo.read_bytes()
    assert data.startswith(b"MZ")
    assert b"This program cannot be run in DOS mode." in data

    # 4. eicar.com (Standard EICAR string and official SHA-256)
    eicar = files["eicar"]
    if eicar.exists():
        assert eicar.read_bytes() == EICAR_STRING
        expected_eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        assert hashlib.sha256(eicar.read_bytes()).hexdigest() == expected_eicar_sha256

    # 5. suspicious_notes.txt
    notes = files["notes"].read_text(encoding="utf-8")
    assert "198.51.100.77" in notes
    assert "c2-update-service.darknet-relay.org" in notes
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in notes

    # 6. sample.pcap (Valid libpcap file)
    pcap = files["pcap"].read_bytes()
    magic = struct.unpack("<I", pcap[:4])[0]
    assert magic == 0xA1B2C3D4
    records = parse_pcap_in_memory(pcap)
    assert len(records) == 3


def test_sleuthkit_adapter(demo_env):
    """Verify The Sleuth Kit fls adapter handles availability degradation and parsing."""
    app = demo_env["app"]
    case_id = demo_env["case_id"]
    lead_id = demo_env["lead_id"]

    # 1. When fls is unavailable: graceful degradation without throwing
    with app.app_context():
        with patch("app.adapters.sleuthkit.is_tool_available", return_value=False):
            res = list_disk_image_files(case_id, 1, lead_id)
            assert res["available"] is False
            assert res["success"] is False
            assert "not installed or available" in res["error"]
            assert res["entries"] == []

        # 2. Mocked successful fls run output
        mock_output = (
            "d/d 144-144-1: /evidence_dir\n"
            "r/r 128-128-3: /evidence_dir/passwords.txt\n"
            "r/r * 129-128-3: /evidence_dir/deleted_secret.doc\n"
            "+ r/r 130-128-3: (null)\n"
        )
        mock_tool_res = {
            "status": "done",
            "returncode": 0,
            "stdout": mock_output,
            "stderr": "",
        }

        with patch("app.adapters.sleuthkit.is_tool_available", return_value=True):
            with patch("app.adapters.sleuthkit.run_tool", return_value=mock_tool_res):
                res = list_disk_image_files(case_id, 1, lead_id)
                assert res["available"] is True
                assert res["success"] is True
                entries = res["entries"]
                assert len(entries) >= 3

                # First entry: directory
                assert entries[0]["type"] == "directory"
                assert entries[0]["path"] == "/evidence_dir"
                assert entries[0]["is_deleted"] is False

                # Second entry: file
                assert entries[1]["type"] == "file"
                assert entries[1]["path"] == "/evidence_dir/passwords.txt"
                assert entries[1]["is_deleted"] is False

                # Third entry: deleted file
                assert entries[2]["type"] == "file"
                assert entries[2]["path"] == "/evidence_dir/deleted_secret.doc"
                assert entries[2]["is_deleted"] is True


def test_end_to_end_investigation_lifecycle(demo_env, tmp_path):
    """
    Complete end-to-end multi-stage investigation workflow:
      1. Intake JPEG and extract EXIF/GPS
      2. Intake auth.log and run automated log analysis (SUCCESS_AFTER_FAILURES finding)
      3. Intake suspicious notes and ingest extracted IOCs
      4. Verify custody chain integrity
      5. Draft, generate, and cryptographically sign Section 63 BSA report
      6. Verify report authenticity and demonstrate rejection upon tampering
    """
    app = demo_env["app"]
    case_id = demo_env["case_id"]
    lead_id = demo_env["lead_id"]
    analyst_id = demo_env["analyst_id"]
    vault_dir = demo_env["vault_dir"]
    work_dir = demo_env["work_dir"]
    reports_dir = demo_env["reports_dir"]
    keys_dir = demo_env["keys_dir"]

    # Generate demo artifacts in temp folder
    demo_files = generate_all_demo_data(tmp_path / "artifacts")

    with app.app_context():
        # --- Stage 1: Ingest JPEG Photo and Analyze Metadata ---
        photo_bytes = demo_files["sample_photo"].read_bytes()
        storage_photo = FileStorage(stream=io.BytesIO(photo_bytes), filename="field_photo.jpg")
        photo_ev_id = intake_evidence(case_id, storage_photo, analyst_id, vault_dir, work_dir, "image/jpeg")

        meta_res = analyze_evidence_metadata(case_id, photo_ev_id, analyst_id, vault_dir)
        assert meta_res["native"]["camera_make"] == "Nikon"
        assert meta_res["native"]["camera_model"] == "D850"
        assert meta_res["gps"] is not None
        assert meta_res["gps"]["latitude"] is not None

        # Verify timeline received metadata capture event
        events = query_db("SELECT * FROM events WHERE case_id = ?", (case_id,))
        assert len(events) >= 1

        # --- Stage 2: Ingest auth.log and Run Log Analyzer ---
        log_bytes = demo_files["auth_log"].read_bytes()
        storage_log = FileStorage(stream=io.BytesIO(log_bytes), filename="auth.log")
        log_ev_id = intake_evidence(case_id, storage_log, analyst_id, vault_dir, work_dir, "text/plain")

        log_res = analyze_log_evidence(
            case_id=case_id,
            evidence_id=log_ev_id,
            log_format="auth.log",
            acting_user_id=analyst_id,
            vault_dir=vault_dir,
        )
        findings = log_res.get("findings", [])
        rules_triggered = {f["rule"]: f for f in findings}

        assert "SUCCESS_AFTER_FAILURES" in rules_triggered
        assert rules_triggered["SUCCESS_AFTER_FAILURES"]["severity"] == "Critical"
        assert "BRUTE_FORCE" in rules_triggered

        # Verify IP 198.51.100.77 was extracted as an IOC
        iocs = query_db("SELECT * FROM iocs WHERE case_id = ? AND value = '198.51.100.77'", (case_id,))
        assert len(iocs) == 1

        # --- Stage 3: Ingest Suspicious Notes IOCs ---
        notes_text = demo_files["notes"].read_text(encoding="utf-8")
        ioc_summary = extract_and_store_iocs(case_id, photo_ev_id, notes_text, source="incident_notes")
        assert ioc_summary["total"] > 0

        # --- Stage 4: Verify Custody Hash Chain ---
        chain_audit = verify_chain(case_id)
        assert chain_audit["status"] == "OK"
        assert chain_audit["entries_count"] >= 2

        # --- Stage 5: Generate and Digitally Sign Report ---
        pdf_path = generate_forensic_report(case_id, lead_id, reports_dir)
        assert pdf_path.exists()

        pdf_sha = hashlib.sha256(pdf_path.read_bytes()).hexdigest()
        report_id = execute_db(
            """
            INSERT INTO reports (case_id, file_name, sha256, signature, signed_by, chain_head_hash)
            VALUES (?, ?, ?, '', ?, ?)
            """,
            (case_id, pdf_path.name, pdf_sha, lead_id, chain_audit.get("head_hash", "00" * 32)),
        )

        # Sign report using Lead Examiner's password
        signed_ok = sign_report(report_id, lead_id, "LeadPass123!@#", keys_dir)
        assert signed_ok is True

        rep_signed = query_db("SELECT signature FROM reports WHERE id = ?", (report_id,), one=True)
        assert rep_signed["signature"] != ""

        # --- Stage 6: Verify Report Authenticity ---
        ver_clean = verify_report_signature(pdf_path.read_bytes(), report_id)
        assert ver_clean["authentic"] is True
        assert "Lead Investigator" in ver_clean["signer"]

        # Demonstrate Tamper Rejection: Alter 1 byte of the PDF
        tampered_pdf = bytearray(pdf_path.read_bytes())
        tampered_pdf[-100] = (tampered_pdf[-100] + 1) % 256
        ver_tampered = verify_report_signature(bytes(tampered_pdf), report_id)
        assert ver_tampered["authentic"] is False
        assert "modified" in ver_tampered["reason"].lower()


def test_demo_script_tamper_and_watchdog_scenarios(demo_env):
    """Verify Scene 3 (broken custody entry detection) and Scene 4 (compromised vault detection)."""
    app = demo_env["app"]
    case_id = demo_env["case_id"]
    lead_id = demo_env["lead_id"]
    vault_dir = demo_env["vault_dir"]
    work_dir = demo_env["work_dir"]

    with app.app_context():
        # Intake an evidence file
        storage = FileStorage(stream=io.BytesIO(b"critical state evidence"), filename="state.bin")
        ev_id = intake_evidence(case_id, storage, lead_id, vault_dir, work_dir, "raw")

        # 1. Verify clean custody chain
        chain_clean = verify_chain(case_id)
        assert chain_clean["status"] == "OK"

        # 2. Simulate Scene 3: Direct custody tampering (temporarily disable trigger)
        execute_db("DROP TRIGGER IF EXISTS trg_custody_log_no_update")
        execute_db(
            "UPDATE custody_log SET detail_json = '{\"tampered\": true}' WHERE case_id = ?",
            (case_id,),
        )

        chain_tampered = verify_chain(case_id)
        assert chain_tampered["status"] == "BROKEN"
        assert chain_tampered["broken_at_entry"] is not None

        # Re-instate trigger from schema
        with open("app/schema.sql", "r", encoding="utf-8") as f:
            schema = f.read()
        trg_start = schema.find("CREATE TRIGGER IF NOT EXISTS trg_custody_log_no_update")
        trg_sql = schema[trg_start : schema.find("END;", trg_start) + 4]
        execute_db(trg_sql)

        # 3. Simulate Scene 4: Mutate vault encrypted file on disk
        ev_item = get_evidence_details(ev_id)
        stored_name = ev_item["stored_name"]
        enc_path = vault_dir / stored_name
        assert enc_path.exists()

        # Temporarily enable write permissions on read-only file and flip 1 byte
        os.chmod(str(enc_path), stat.S_IWRITE | stat.S_IREAD)
        with open(enc_path, "r+b") as f:
            f.seek(16)
            b = f.read(1)
            f.seek(16)
            f.write(bytes([b[0] ^ 0xFF]))
        os.chmod(str(enc_path), stat.S_IREAD)

        # Run integrity watchdog scan
        sweep_state = run_integrity_watchdog_job(app)
        assert sweep_state["last_status"] == "COMPROMISED_DETECTED"
        assert sweep_state["last_compromised_count"] >= 1

        # Check evidence status in database
        ev_row = query_db("SELECT integrity_status FROM evidence WHERE id = ?", (ev_id,), one=True)
        assert ev_row["integrity_status"] == "COMPROMISED"
