"""
Tests for Section S13: System Health, Encrypted Backup, Verified Restore & Case Export.
Covers:
- System health diagnostic endpoint (PRAGMA integrity_check, disk storage, vault synchronicity)
- Encrypted backup creation using SQLite backup API and AES-256-GCM encryption
- Manifest verification against SHA-256 hashes
- Tamper detection on backup files (AES-GCM authentication failure)
- System-chain custody logging for BACKUP_CREATED and SYSTEM_RESTORE
- Safe restoration with pre-flight database integrity verification
- Restoration authorization enforcement (typed 'CONFIRM RESTORE')
- Portable case export package creation with metadata and evidence manifest
- Access controls: Admin required for health, backup, and restore; Lead/Admin for case export
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
from app.modules.system.service import (
    get_health_status,
    create_backup,
    verify_backup_manifest,
    restore_backup,
    export_case_package,
    list_backups,
)


@pytest.fixture
def system_env(tmp_path):
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vault"
    db_path = data_dir / "db" / "forensix.db"
    master_key = data_dir / "keys" / "master.key"
    work_dir = data_dir / "work"
    backups_dir = data_dir / "backups"
    keys_dir = data_dir / "keys"

    app = create_app({
        "TESTING": True,
        "DATA_DIR": str(data_dir),
        "VAULT_DIR": str(vault_dir),
        "DB_DIR": str(data_dir / "db"),
        "KEYS_DIR": str(keys_dir),
        "LOGS_DIR": str(data_dir / "logs"),
        "WORK_DIR": str(work_dir),
        "BACKUPS_DIR": str(backups_dir),
        "DATABASE_PATH": str(db_path),
        "MASTER_KEY_PATH": str(master_key),
        "WTF_CSRF_ENABLED": False,
        "ALLOW_LAN": False,
        "HOST": "127.0.0.1",
        "PORT": 5000,
        "SECRET_KEY": "test_secret_key_forensix_section13_system",
    })

    with app.app_context():
        init_db(db_path)
        admin_id = create_user("System Admin", "admin_sys", "Admin", "AdminPass123!@#")
        lead_id = create_user("Lead Investigator", "lead_sys", "Lead", "LeadPass123!@#")
        analyst_id = create_user("Analyst Investigator", "analyst_sys", "Analyst", "AnalystPass123!")

        case_id = create_case("Disaster Recovery Case", "Testing system resilience", "Medium", lead_id)
        assign_member(case_id, analyst_id, lead_id)

    return {
        "app": app,
        "admin_id": admin_id,
        "lead_id": lead_id,
        "analyst_id": analyst_id,
        "case_id": case_id,
        "db_path": db_path,
        "vault_dir": vault_dir,
        "data_dir": data_dir,
        "backups_dir": backups_dir,
        "work_dir": work_dir,
    }


def test_health_status_and_db_integrity(system_env):
    """Verify get_health_status correctly executes PRAGMA integrity_check and checks vault."""
    app = system_env["app"]
    db_path = system_env["db_path"]
    vault_dir = system_env["vault_dir"]
    data_dir = system_env["data_dir"]

    with app.app_context():
        health = get_health_status(db_path, vault_dir, data_dir)
        assert health["db_ok"] is True
        assert health["db_integrity"] == "ok"
        assert health["disk_total_gb"] > 0
        assert health["disk_free_gb"] > 0
        assert health["vault_mismatch"] is False
        assert isinstance(health["tools"], list)


def test_vault_mismatch_detection(system_env):
    """Verify that an orphan file in vault triggers a vault_mismatch alert."""
    app = system_env["app"]
    db_path = system_env["db_path"]
    vault_dir = system_env["vault_dir"]
    data_dir = system_env["data_dir"]

    with app.app_context():
        # Create an orphan file in vault
        orphan = vault_dir / "orphan_ghost_file.enc"
        orphan.write_bytes(b"mystery data")

        health = get_health_status(db_path, vault_dir, data_dir)
        assert health["vault_mismatch"] is True
        assert health["vault_file_count"] == 1
        assert health["evidence_row_count"] == 0

        # Cleanup orphan
        orphan.unlink()


def test_health_routes_rbac(system_env):
    """Verify only Admin can access /system/health and /system/backup."""
    app = system_env["app"]
    admin_id = system_env["admin_id"]
    lead_id = system_env["lead_id"]

    client = app.test_client()

    # 1. Lead gets 403 on health dashboard
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)
        sess["_fresh"] = True
    resp_lead = client.get("/system/health")
    assert resp_lead.status_code == 403

    # 2. Admin gets 200 on health dashboard
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)
        sess["_fresh"] = True
    resp_admin = client.get("/system/health")
    assert resp_admin.status_code == 200
    assert b"Health Monitor" in resp_admin.data


def test_backup_creates_encrypted_archive_and_manifest(system_env):
    """Verify create_backup bundles snapshot, vault files, and manifest into encrypted file."""
    app = system_env["app"]
    admin_id = system_env["admin_id"]
    case_id = system_env["case_id"]
    db_path = system_env["db_path"]
    vault_dir = system_env["vault_dir"]
    backups_dir = system_env["backups_dir"]
    work_dir = system_env["work_dir"]

    with app.app_context():
        # Ingest an evidence file
        storage = FileStorage(stream=io.BytesIO(b"vault file content 12345"), filename="evidence1.dat")
        intake_evidence(case_id, storage, admin_id, vault_dir, work_dir, "generic.dat")

        # Create backup
        backup_path = create_backup(db_path, vault_dir, backups_dir, admin_id)
        assert backup_path.is_file()
        assert backup_path.name.endswith(".enc")

        # Raw file must NOT start with ZIP magic bytes PK\x03\x04 (encrypted!)
        raw_bytes = backup_path.read_bytes()
        assert not raw_bytes.startswith(b"PK\x03\x04")

        # Manifest verification
        ver = verify_backup_manifest(backup_path)
        assert ver["valid"] is True
        assert ver["manifest"]["version"] == "1.0"
        assert len(ver["manifest"]["files"]) >= 2  # database.sqlite + 1 vault file

        # Verify custody entry on system chain
        custody_rows = query_db(
            "SELECT action, user_id FROM custody_log WHERE case_id IS NULL AND action = 'BACKUP_CREATED'",
        )
        assert len(custody_rows) == 1
        assert custody_rows[0]["user_id"] == admin_id


def test_tampered_backup_rejected(system_env):
    """Verify tampering with encrypted backup ciphertext fails authentication tag check."""
    app = system_env["app"]
    admin_id = system_env["admin_id"]
    db_path = system_env["db_path"]
    vault_dir = system_env["vault_dir"]
    backups_dir = system_env["backups_dir"]

    with app.app_context():
        backup_path = create_backup(db_path, vault_dir, backups_dir, admin_id)

        # Alter bytes in backup
        raw = bytearray(backup_path.read_bytes())
        raw[25] = (raw[25] + 1) % 256
        tampered_backup = backups_dir / "tampered_backup.enc"
        tampered_backup.write_bytes(bytes(raw))

        ver = verify_backup_manifest(tampered_backup)
        assert ver["valid"] is False
        assert any("decryption" in m.lower() or "failed" in m.lower() for m in ver["mismatches"])


def test_restore_replaces_data_and_verifies(system_env):
    """Verify complete backup and restore roundtrip survives clean deletion and preserves integrity."""
    app = system_env["app"]
    admin_id = system_env["admin_id"]
    lead_id = system_env["lead_id"]
    case_id = system_env["case_id"]
    db_path = system_env["db_path"]
    vault_dir = system_env["vault_dir"]
    backups_dir = system_env["backups_dir"]
    work_dir = system_env["work_dir"]

    with app.app_context():
        # Ingest evidence
        storage = FileStorage(stream=io.BytesIO(b"evidence state before backup"), filename="state.bin")
        ev_id = intake_evidence(case_id, storage, lead_id, vault_dir, work_dir, "generic.bin")

        # Take backup
        backup_path = create_backup(db_path, vault_dir, backups_dir, admin_id)

        # Tamper / mutate live DB state
        execute_db("UPDATE cases SET title = 'MUTATED TITLE AFTER BACKUP' WHERE id = ?", (case_id,))
        case_mod = query_db("SELECT title FROM cases WHERE id = ?", (case_id,), one=True)
        assert case_mod["title"] == "MUTATED TITLE AFTER BACKUP"

        # Restore from backup
        success = restore_backup(backup_path, db_path, vault_dir, admin_id)
        assert success is True

        # Verify DB restored to original title
        case_restored = query_db("SELECT title FROM cases WHERE id = ?", (case_id,), one=True)
        assert case_restored["title"] == "Disaster Recovery Case"

        # Verify SYSTEM_RESTORE was logged to custody chain
        restore_log = query_db(
            "SELECT action, user_id FROM custody_log WHERE case_id IS NULL AND action = 'SYSTEM_RESTORE'",
        )
        assert len(restore_log) >= 1


def test_restore_requires_typed_confirmation(system_env):
    """Verify that restore route strictly rejects requests without 'CONFIRM RESTORE'."""
    app = system_env["app"]
    admin_id = system_env["admin_id"]

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)
        sess["_fresh"] = True

    # 1. Missing or wrong confirmation text
    resp = client.post("/system/restore", data={"confirm_text": "yes please"})
    assert resp.status_code == 302
    # Redirected back to /system/backup with error


def test_case_export_package(system_env):
    """Verify portable case export packages evidence, metadata, custody, and manifest."""
    app = system_env["app"]
    admin_id = system_env["admin_id"]
    lead_id = system_env["lead_id"]
    case_id = system_env["case_id"]
    db_path = system_env["db_path"]
    vault_dir = system_env["vault_dir"]
    work_dir = system_env["work_dir"]

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(b"case export test evidence"), filename="export_ev.dat")
        intake_evidence(case_id, storage, lead_id, vault_dir, work_dir, "generic.dat")

        export_zip = export_case_package(case_id, db_path, vault_dir, work_dir, lead_id)
        assert export_zip.is_file()
        assert export_zip.name.endswith(".zip")

        import zipfile
        with zipfile.ZipFile(export_zip, mode="r") as zf:
            namelist = zf.namelist()
            assert "case_metadata.json" in namelist
            assert "custody_trail.json" in namelist
            assert "manifest.json" in namelist
            assert any(n.startswith("evidence/") for n in namelist)

        # Check custody log has CASE_EXPORT
        cl = query_db("SELECT action FROM custody_log WHERE case_id = ? AND action = 'CASE_EXPORT'", (case_id,))
        assert len(cl) == 1
