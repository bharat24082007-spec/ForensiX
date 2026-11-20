"""
Tests for Section S5: Custody Chain & Integrity Checker.
Verifies append-only hash-chained custody logging, canonical JSON formatting,
mathematical chain verification, SQLite trigger immutability, exact-entry tamper detection,
and automated evidence integrity watchdog sweeps.
"""

from __future__ import annotations

import io
import os
import stat
import sqlite3
from pathlib import Path
import pytest
from werkzeug.datastructures import FileStorage

from app import create_app
from app.db import execute_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.custody.service import (
    append as custody_append,
    verify_chain,
    get_custody_entries,
    canonical_json,
    compute_entry_hash,
    GENESIS_PREV_HASH,
)
from app.modules.evidence.service import intake_evidence
from app.modules.integrity.service import verify_evidence, verify_all_case_evidence
from app.modules.integrity.watchdog import run_integrity_watchdog_job, get_watchdog_state


@pytest.fixture
def custody_app(tmp_path: Path):
    """Fixture providing an isolated application instance with database and vault."""
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


def test_canonical_json_and_hash_determinism():
    """Verify canonical JSON produces sorted keys and identical hash regardless of input order."""
    detail_a = {"beta": 2, "alpha": "test", "gamma": [1, 2, 3]}
    detail_b = {"gamma": [1, 2, 3], "alpha": "test", "beta": 2}

    json_a = canonical_json(1, None, 5, "UPLOAD", detail_a, "2026-11-19T10:00:00Z")
    json_b = canonical_json(1, None, 5, "UPLOAD", detail_b, "2026-11-19T10:00:00Z")

    assert json_a == json_b
    assert json_a == '{"action":"UPLOAD","case_id":1,"detail":{"alpha":"test","beta":2,"gamma":[1,2,3]},"evidence_id":null,"timestamp_utc":"2026-11-19T10:00:00Z","user_id":5}'

    hash_a = compute_entry_hash(1, None, 5, "UPLOAD", detail_a, "2026-11-19T10:00:00Z", GENESIS_PREV_HASH)
    hash_b = compute_entry_hash(1, None, 5, "UPLOAD", detail_b, "2026-11-19T10:00:00Z", GENESIS_PREV_HASH)
    assert hash_a == hash_b
    assert len(hash_a) == 64


def test_custody_append_and_verify_ok(custody_app):
    """Verify appending sequential entries creates a valid cryptographic chain from genesis."""
    with custody_app.app_context():
        lead_id = create_user("Lead User", "lead_user", "Lead", "Pass123456789!")
        case_id = create_case("Custody Test Case", "Testing custody chain", "High", lead_id)

        # Append 4 more entries to make 5 total (case creation is entry #1)
        for i in range(2, 6):
            custody_append(
                case_id=case_id,
                evidence_id=None,
                user_id=lead_id,
                action=f"ANALYSIS_STEP_{i}",
                detail={"step": i, "notes": f"Executed analysis step {i}"},
            )

        # Verify chain
        result = verify_chain(case_id)
        assert result["status"] == "OK"
        assert result["entries_count"] == 5
        assert result["head_hash"] != GENESIS_PREV_HASH

        # Verify sequential prev_hash chaining
        entries = get_custody_entries(case_id)
        assert len(entries) == 5
        # Ordered DESC by ID in get_custody_entries
        entries_asc = sorted(entries, key=lambda x: x["id"])
        assert entries_asc[0]["prev_hash"] == GENESIS_PREV_HASH
        for j in range(1, len(entries_asc)):
            assert entries_asc[j]["prev_hash"] == entries_asc[j - 1]["entry_hash"]


def test_system_chain_append_and_verify_ok(custody_app):
    """Verify the system-wide custody chain (case_id is NULL) works independently."""
    with custody_app.app_context():
        admin_id = create_user("Admin User", "sysadmin", "Admin", "Pass123456789!")

        custody_append(
            case_id=None,
            evidence_id=None,
            user_id=admin_id,
            action="USER_LOGIN",
            detail={"username": "sysadmin"},
        )
        custody_append(
            case_id=None,
            evidence_id=None,
            user_id=admin_id,
            action="USER_CREATED",
            detail={"created_user": "analyst1"},
        )

        result = verify_chain(case_id=None)
        assert result["status"] == "OK"
        assert result["entries_count"] >= 2


def test_custody_sqlite_triggers_block_tampering(custody_app):
    """Verify database triggers prevent direct UPDATE or DELETE operations on custody_log."""
    with custody_app.app_context():
        lead_id = create_user("Lead Lead", "lead_trigger", "Lead", "Pass123456789!")
        case_id = create_case("Trigger Case", "Trigger enforcement", "Medium", lead_id)

        rows = query_db("SELECT id FROM custody_log WHERE case_id = ?", (case_id,))
        entry_id = rows[0]["id"]

        # Attempt UPDATE directly in SQL
        with pytest.raises(Exception) as exc_info:
            execute_db("UPDATE custody_log SET action = 'MALICIOUS_OVERWRITE' WHERE id = ?", (entry_id,))
        assert "APPEND-ONLY" in str(exc_info.value).upper() or "TRIGGER" in str(exc_info.value).upper()

        # Attempt DELETE directly in SQL
        with pytest.raises(Exception) as exc_info:
            execute_db("DELETE FROM custody_log WHERE id = ?", (entry_id,))
        assert "APPEND-ONLY" in str(exc_info.value).upper() or "TRIGGER" in str(exc_info.value).upper()


def test_tamper_detection_reports_exact_entry(custody_app):
    """Verify that tampering with an entry's content is detected at the exact broken entry."""
    with custody_app.app_context():
        lead_id = create_user("Lead Tamper", "lead_tamper", "Lead", "Pass123456789!")
        case_id = create_case("Tamper Test", "Tamper detection test", "Medium", lead_id)

        for i in range(2, 6):
            custody_append(
                case_id=case_id,
                evidence_id=None,
                user_id=lead_id,
                action=f"STEP_{i}",
                detail={"step": i},
            )

        # Chain is currently intact
        assert verify_chain(case_id)["status"] == "OK"

        # Fetch entries to target entry #3
        entries_asc = sorted(get_custody_entries(case_id), key=lambda x: x["id"])
        target_entry = entries_asc[2]  # 3rd entry (index 2)
        target_id = target_entry["id"]

        # Temporarily drop update trigger to simulate offline or malicious DB tampering
        execute_db("DROP TRIGGER IF EXISTS trg_custody_log_no_update")
        # Tamper with the details of entry #3
        execute_db(
            "UPDATE custody_log SET detail_json = ? WHERE id = ?",
            ('{"step":3,"tampered":true}', target_id),
        )
        # Restore trigger
        execute_db(
            """
            CREATE TRIGGER trg_custody_log_no_update
            BEFORE UPDATE ON custody_log
            BEGIN
                SELECT RAISE(ABORT, 'custody_log is append-only');
            END;
            """
        )

        # Verification must now fail exactly at target_id
        check = verify_chain(case_id)
        assert check["status"] == "BROKEN"
        assert check["broken_at_entry"] == target_id
        assert check["sequence"] == 3
        assert "Content integrity broken" in check["reason"]


def test_tampered_prev_hash_breaks_chain(custody_app):
    """Verify that breaking the linkage (prev_hash) is caught with sequence and entry ID."""
    with custody_app.app_context():
        lead_id = create_user("Lead Link", "lead_link", "Lead", "Pass123456789!")
        case_id = create_case("Link Case", "Link tampering", "Medium", lead_id)

        for i in range(2, 6):
            custody_append(
                case_id=case_id,
                evidence_id=None,
                user_id=lead_id,
                action=f"AUDIT_{i}",
                detail={"idx": i},
            )

        entries_asc = sorted(get_custody_entries(case_id), key=lambda x: x["id"])
        target_entry = entries_asc[3]  # 4th entry
        target_id = target_entry["id"]

        execute_db("DROP TRIGGER IF EXISTS trg_custody_log_no_update")
        execute_db("UPDATE custody_log SET prev_hash = ? WHERE id = ?", ("f" * 64, target_id))
        execute_db(
            """
            CREATE TRIGGER trg_custody_log_no_update
            BEFORE UPDATE ON custody_log
            BEGIN
                SELECT RAISE(ABORT, 'custody_log is append-only');
            END;
            """
        )

        check = verify_chain(case_id)
        assert check["status"] == "BROKEN"
        assert check["broken_at_entry"] == target_id
        assert check["sequence"] == 4
        assert "Chain linkage broken" in check["reason"]


def test_watchdog_detects_corrupted_vault_file_and_flags_compromised(custody_app):
    """Verify background watchdog detects physical bit tampering, marks COMPROMISED, and logs VERIFY_FAIL."""
    with custody_app.app_context():
        vault_dir = Path(custody_app.config["VAULT_DIR"])
        work_dir = Path(custody_app.config["WORK_DIR"])

        lead_id = create_user("Lead Watch", "lead_watch", "Lead", "Pass123456789!")
        case_id = create_case("Watchdog Case", "Testing watchdog", "Critical", lead_id)

        payload = b"Top secret forensic disk capture bytes to verify integrity."
        storage = FileStorage(stream=io.BytesIO(payload), filename="disk_image.raw", content_type="application/octet-stream")

        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="Disk Image",
            uploaded_by_user_id=lead_id,
        )

        # Verify initial health
        initial_check = verify_evidence(ev_id, vault_dir=vault_dir)
        assert initial_check["status"] == "VERIFIED"

        # Tamper with the encrypted vault file on physical storage
        row = query_db("SELECT stored_name FROM evidence WHERE id = ?", (ev_id,), one=True)
        vault_file = vault_dir / row["stored_name"]
        assert vault_file.is_file()

        # Unlock write permission on Windows, mutate ciphertext, restore read-only
        os.chmod(vault_file, stat.S_IWRITE | stat.S_IREAD)
        with open(vault_file, "r+b") as f:
            f.seek(32)  # Skip past the 16-byte salt and 12-byte nonce
            corrupt_bytes = f.read(16)
            f.seek(32)
            f.write(bytes([b ^ 0xFF for b in corrupt_bytes]))
        os.chmod(vault_file, stat.S_IREAD)

        # Run watchdog sweep
        sweep_state = run_integrity_watchdog_job(custody_app)
        assert sweep_state["last_status"] == "COMPROMISED_DETECTED"
        assert sweep_state["last_compromised_count"] == 1

        # Check evidence status in database
        ev_row = query_db("SELECT integrity_status FROM evidence WHERE id = ?", (ev_id,), one=True)
        assert ev_row["integrity_status"] == "COMPROMISED"

        # Check custody log for VERIFY_FAIL entry
        fails = query_db(
            "SELECT action, detail_json FROM custody_log WHERE evidence_id = ? AND action = 'VERIFY_FAIL'",
            (ev_id,),
        )
        assert len(fails) >= 1


def test_custody_routes_and_access_control(custody_app):
    """Verify HTTP endpoints for case custody trail, on-demand verification, and system chain."""
    client = custody_app.test_client()

    with custody_app.app_context():
        lead_id = create_user("Lead Investigator", "lead_custody", "Lead", "Pass123456789!")
        analyst_id = create_user("Analyst Investigator", "analyst_custody", "Analyst", "Pass123456789!")
        outsider_id = create_user("Outsider Analyst", "outsider_custody", "Analyst", "Pass123456789!")
        admin_id = create_user("Admin User", "admin_custody", "Admin", "Pass123456789!")

        case_id = create_case("Route Test Case", "Custody route tests", "High", lead_id)
        assign_member(case_id, analyst_id, lead_id)

    # 1. Lead accesses custody trail -> 200 OK
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)

    resp = client.get(f"/cases/{case_id}/custody")
    assert resp.status_code == 200
    assert b"Custody Chain Cryptographically Intact" in resp.data
    assert b"Verify Chain" in resp.data

    # 2. Trigger on-demand verification POST -> redirect with flash
    verify_resp = client.post(f"/cases/{case_id}/verify", data={"verify_files": "1"}, follow_redirects=True)
    assert verify_resp.status_code == 200
    assert b"Chain Intact" in verify_resp.data

    # 3. Outsider accesses custody trail -> 404 (separation of duties)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)

    resp_out = client.get(f"/cases/{case_id}/custody")
    assert resp_out.status_code == 404

    # 4. Admin accesses system audit chain -> 200 OK
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)

    sys_resp = client.get("/system/chain")
    assert sys_resp.status_code == 200
    assert b"System Audit Chain" in sys_resp.data
    assert b"Evidence Integrity Watchdog" in sys_resp.data
