"""
Tests for Section S7: Metadata & EXIF Analysis.
Verifies deep metadata extraction via ExifTool and native fallbacks (Pillow, pypdf, pefile),
UTC timestamp normalization into events table, anomaly detection (JPEG EOF trailing overlay,
high Shannon entropy, MIME discrepancies), and offline GPS coordinate rendering.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import pytest
from PIL import Image
from werkzeug.datastructures import FileStorage

from app import create_app
from app.db import execute_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.evidence.service import intake_evidence
from app.modules.metadata.service import (
    compute_shannon_entropy,
    parse_timestamp_to_utc,
    check_jpeg_trailing_data,
    analyze_evidence_metadata,
)


@pytest.fixture
def metadata_app(tmp_path: Path):
    """Fixture providing an isolated application instance with data folders."""
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


def test_shannon_entropy_calculation():
    """Verify Shannon entropy calculation reflects data randomness."""
    low_entropy_bytes = b"A" * 1000
    high_entropy_bytes = os.urandom(1000)

    low_val = compute_shannon_entropy(low_entropy_bytes)
    high_val = compute_shannon_entropy(high_entropy_bytes)

    assert low_val == 0.0
    assert high_val > 7.5


def test_timestamp_utc_normalization():
    """Verify metadata timestamps from varied formats are strictly normalized to ISO UTC."""
    # EXIF format
    exif_res = parse_timestamp_to_utc("2026:08:14 10:15:30")
    assert exif_res is not None
    assert exif_res[0] == "2026-08-14T10:15:30+00:00"

    # PDF format
    pdf_res = parse_timestamp_to_utc("D:20260814101530")
    assert pdf_res is not None
    assert pdf_res[0] == "2026-08-14T10:15:30+00:00"

    # ISO format
    iso_res = parse_timestamp_to_utc("2026-08-14T10:15:30Z")
    assert iso_res is not None
    assert iso_res[0] == "2026-08-14T10:15:30+00:00"


def test_jpeg_trailing_data_detection():
    """Verify detection of extraneous payload bytes appended after JPEG EOF marker (FF D9)."""
    # Clean JPEG stub
    clean_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xd9"
    assert check_jpeg_trailing_data(clean_jpeg) is None

    # Stego JPEG with appended payload
    stego_payload = b"SECRET_EXTRANEOUS_PAYLOAD_DATA_HERE"
    stego_jpeg = clean_jpeg + stego_payload

    check = check_jpeg_trailing_data(stego_jpeg)
    assert check is not None
    assert check["trailing_size"] == len(stego_payload)
    assert check["trailing_entropy"] > 0.0


def test_jpeg_exif_camera_time_and_gps_extraction(metadata_app):
    """Verify EXIF metadata extraction extracts camera, capture time, GPS, and populates events."""
    with metadata_app.app_context():
        vault_dir = Path(metadata_app.config["VAULT_DIR"])
        work_dir = Path(metadata_app.config["WORK_DIR"])

        lead_id = create_user("Lead User", "lead_meta1", "Lead", "Pass123456789!")
        case_id = create_case("Metadata Case", "EXIF testing", "Medium", lead_id)

        # Generate JPEG with EXIF tags
        img = Image.new("RGB", (64, 64), color="red")
        exif = img.getexif()
        exif[0x010F] = "Nikon"  # Make
        exif[0x0110] = "D850"   # Model
        exif[0x0132] = "2026:07:10 15:45:00"  # DateTime
        
        # Add GPS Info
        gps_ifd = exif.get_ifd(0x8825)
        gps_ifd[1] = "N"
        gps_ifd[2] = (37.0, 46.0, 30.0)
        gps_ifd[3] = "W"
        gps_ifd[4] = (122.0, 25.0, 10.0)

        buf = io.BytesIO()
        img.save(buf, format="JPEG", exif=exif)
        jpeg_bytes = buf.getvalue()

        storage = FileStorage(stream=io.BytesIO(jpeg_bytes), filename="camera_photo.jpg", content_type="image/jpeg")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="Image",
            uploaded_by_user_id=lead_id,
        )

        # Run metadata analysis
        res = analyze_evidence_metadata(case_id, ev_id, acting_user_id=lead_id)

        assert res["evidence_id"] == ev_id
        # Verify GPS parsed (37.775 N, -122.419444 W)
        assert res["gps"] is not None
        assert abs(res["gps"]["latitude"] - 37.775) < 0.01
        assert abs(res["gps"]["longitude"] - (-122.419444)) < 0.01
        assert "N" in res["gps"]["text"]
        assert "W" in res["gps"]["text"]

        # Verify timeline events created in database
        event_rows = query_db(
            "SELECT timestamp_utc, source_type, raw_line FROM events WHERE evidence_id = ?",
            (ev_id,),
        )
        assert len(event_rows) >= 1
        assert event_rows[0]["source_type"] == "metadata"
        assert "2026-07-10T15:45:00" in event_rows[0]["timestamp_utc"]


def test_fake_jpg_executable_flagged_as_suspicious(metadata_app):
    """Verify an executable disguised with .jpg extension is flagged with high-severity findings."""
    with metadata_app.app_context():
        vault_dir = Path(metadata_app.config["VAULT_DIR"])
        work_dir = Path(metadata_app.config["WORK_DIR"])

        lead_id = create_user("Lead User", "lead_meta2", "Lead", "Pass123456789!")
        case_id = create_case("Disguised File Case", "Malware testing", "Critical", lead_id)

        # Fake PE executable header
        fake_exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 200
        storage = FileStorage(stream=io.BytesIO(fake_exe), filename="employee_id.jpg", content_type="image/jpeg")

        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="Image",
            uploaded_by_user_id=lead_id,
        )

        res = analyze_evidence_metadata(case_id, ev_id, acting_user_id=lead_id)

        # Check findings table for MIME mismatch
        findings_rows = query_db(
            "SELECT rule, severity, evidence_lines FROM findings WHERE evidence_id = ?",
            (ev_id,),
        )
        assert len(findings_rows) >= 1
        mismatch_found = any(f["rule"] == "MIME_MISMATCH" for f in findings_rows)
        assert mismatch_found is True


def test_jpeg_with_overlay_flagged_in_findings(metadata_app):
    """Verify JPEG with trailing bytes after EOF triggers a Steganography / Overlay finding."""
    with metadata_app.app_context():
        vault_dir = Path(metadata_app.config["VAULT_DIR"])
        work_dir = Path(metadata_app.config["WORK_DIR"])

        lead_id = create_user("Lead User", "lead_meta3", "Lead", "Pass123456789!")
        case_id = create_case("Overlay Case", "Trailing data testing", "High", lead_id)

        img = Image.new("RGB", (32, 32), color="green")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        clean_jpeg_bytes = buf.getvalue()

        # Append hidden data overlay
        stego_bytes = clean_jpeg_bytes + (b"CONFIDENTIAL_EXFILTRATED_RECORD_OFFSET_" * 10)

        storage = FileStorage(stream=io.BytesIO(stego_bytes), filename="stego_photo.jpg", content_type="image/jpeg")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="Image",
            uploaded_by_user_id=lead_id,
        )

        res = analyze_evidence_metadata(case_id, ev_id, acting_user_id=lead_id)

        findings_rows = query_db(
            "SELECT rule, severity FROM findings WHERE evidence_id = ?",
            (ev_id,),
        )
        overlay_found = any(f["rule"] == "JPEG_OVERLAY_DATA" for f in findings_rows)
        assert overlay_found is True


def test_metadata_routes_and_access_control(metadata_app):
    """Verify HTTP endpoints for metadata viewing, re-extraction, and membership enforcement."""
    client = metadata_app.test_client()

    with metadata_app.app_context():
        vault_dir = Path(metadata_app.config["VAULT_DIR"])
        work_dir = Path(metadata_app.config["WORK_DIR"])

        lead_id = create_user("Lead User", "lead_meta4", "Lead", "Pass123456789!")
        outsider_id = create_user("Outsider", "outsider_meta4", "Analyst", "Pass123456789!")
        case_id = create_case("Route Case", "Metadata route testing", "Medium", lead_id)

        img = Image.new("RGB", (32, 32), color="yellow")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")

        storage = FileStorage(stream=io.BytesIO(buf.getvalue()), filename="document.jpg", content_type="image/jpeg")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="Image",
            uploaded_by_user_id=lead_id,
        )

    # 1. Lead accesses metadata view -> 200 OK
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)

    resp = client.get(f"/cases/{case_id}/evidence/{ev_id}/metadata")
    assert resp.status_code == 200
    assert b"Metadata &amp; EXIF Analysis" in resp.data
    assert b"Re-extract Metadata" in resp.data

    # 2. Trigger on-demand re-extraction POST -> redirect with flash
    post_resp = client.post(f"/cases/{case_id}/evidence/{ev_id}/metadata/extract", follow_redirects=True)
    assert post_resp.status_code == 200
    assert b"Metadata re-extraction complete" in post_resp.data

    # 3. Outsider access -> 404
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)

    resp_out = client.get(f"/cases/{case_id}/evidence/{ev_id}/metadata")
    assert resp_out.status_code == 404
