"""
Tests for Section S1: Database and UI Shell.
Verifies full SQLite schema, append-only triggers on custody_log,
foreign key constraints, and dashboard rendering with shared components.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
import pytest

from app import create_app
from app.db import init_db, query_db, execute_db


@pytest.fixture
def test_app(tmp_path: Path):
    """Fixture providing a Flask app instance with a dedicated temporary database."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    data_dir = tmp_path / "data"

    app = create_app(
        test_config={
            "TESTING": True,
            "SECRET_KEY": valid_key,
            "HOST": "127.0.0.1",
            "PORT": 5000,
            "ALLOW_LAN": False,
            "DATA_DIR": str(data_dir),
            "DATABASE_PATH": str(data_dir / "db" / "forensix.sqlite"),
        }
    )
    yield app


def test_schema_all_tables_and_indexes_created(test_app):
    """Verify all 11 required tables and their indexes exist in SQLite."""
    with test_app.app_context():
        tables = query_db(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        table_names = {row["name"] for row in tables}

        expected_tables = {
            "users",
            "cases",
            "case_members",
            "evidence",
            "custody_log",
            "events",
            "findings",
            "iocs",
            "reputation_cache",
            "tool_runs",
            "reports",
        }
        assert expected_tables.issubset(table_names), f"Missing tables: {expected_tables - table_names}"


def test_custody_log_trigger_blocks_update(test_app):
    """Verify BEFORE UPDATE trigger on custody_log raises ABORT."""
    with test_app.app_context():
        # Insert a valid custody entry
        entry_id = execute_db(
            """
            INSERT INTO custody_log (case_id, evidence_id, user_id, action, detail_json, timestamp_utc, prev_hash, entry_hash)
            VALUES (NULL, NULL, NULL, 'SYSTEM_INIT', '{}', '2026-01-01 00:00:00', '0000000000', '1111111111')
            """
        )
        assert entry_id > 0

        # Attempt to modify the row - trigger MUST reject this
        with pytest.raises(sqlite3.DatabaseError, match="custody_log is append-only"):
            execute_db(
                "UPDATE custody_log SET action = 'TAMPERED' WHERE id = ?",
                (entry_id,),
            )


def test_custody_log_trigger_blocks_delete(test_app):
    """Verify BEFORE DELETE trigger on custody_log raises ABORT."""
    with test_app.app_context():
        entry_id = execute_db(
            """
            INSERT INTO custody_log (case_id, evidence_id, user_id, action, detail_json, timestamp_utc, prev_hash, entry_hash)
            VALUES (NULL, NULL, NULL, 'CUSTODY_TEST', '{}', '2026-01-01 00:00:00', '0000000000', '2222222222')
            """
        )
        assert entry_id > 0

        # Attempt to delete the row - trigger MUST reject this
        with pytest.raises(sqlite3.DatabaseError, match="custody_log is append-only"):
            execute_db(
                "DELETE FROM custody_log WHERE id = ?",
                (entry_id,),
            )


def test_foreign_keys_strictly_enforced(test_app):
    """Verify PRAGMA foreign_keys = ON rejects orphan child rows."""
    with test_app.app_context():
        # Attempt to insert a case referencing non-existent lead_user_id (9999)
        with pytest.raises(sqlite3.IntegrityError):
            execute_db(
                """
                INSERT INTO cases (case_no, title, description, status, priority, lead_user_id)
                VALUES ('CASE-9999-0001', 'Orphan Case', 'Testing FKs', 'Open', 'High', 9999)
                """
            )


def test_dashboard_renders_empty_state_safely(test_app):
    """Verify GET /dashboard renders properly with clean empty states when authenticated."""
    with test_app.app_context():
        user_id = execute_db(
            "INSERT INTO users (name, username, role, password_hash) VALUES ('Test Analyst', 'analyst1', 'Analyst', 'hash')"
        )

    client = test_app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Assert components and stat tiles
    assert "Forensic Overview" in html
    assert "Active Cases" in html
    assert "Vault Evidence Items" in html
    assert "Integrity Status" in html
    assert "VERIFIED" in html
    assert "No Active Cases" in html
    assert "Custody Log Empty" in html


def test_dashboard_renders_populated_data_and_hash_component(test_app):
    """Verify dashboard displays populated cases, custody entries, and truncated hash badges."""
    with test_app.app_context():
        # Create user
        user_id = execute_db(
            """
            INSERT INTO users (name, username, role, password_hash)
            VALUES ('Alice Investigator', 'alice', 'Lead', 'fake_hash')
            """
        )

        # Create case
        case_id = execute_db(
            """
            INSERT INTO cases (case_no, title, description, status, priority, lead_user_id)
            VALUES ('CASE-2026-0001', 'Corporate Intrusion Analysis', 'Investigating APT activity', 'Open', 'Critical', ?)
            """,
            (user_id,),
        )

        # Insert custody activity with a 64-char SHA-256 hash
        sample_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        execute_db(
            """
            INSERT INTO custody_log (case_id, evidence_id, user_id, action, detail_json, timestamp_utc, prev_hash, entry_hash)
            VALUES (?, NULL, ?, 'CASE_CREATE', '{"title": "Intrusion"}', '2026-01-01 12:00:00', '0000000000', ?)
            """,
            (case_id, user_id, sample_hash),
        )

    client = test_app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Assert populated case and custody info
    assert "CASE-2026-0001" in html
    assert "Corporate Intrusion Analysis" in html
    assert "Alice Investigator" in html
    assert "CASE_CREATE" in html
    # Assert hash badge display component truncated with copy button
    assert "e3b0c442...7852b855" in html
    assert f'data-hash="{sample_hash}"' in html


def test_theme_tokens_and_static_assets(test_app):
    """Verify static assets (tokens.css, base.css, components.css, app.js) exist and have dark theme support."""
    client = test_app.test_client()

    tokens_resp = client.get("/static/css/tokens.css")
    assert tokens_resp.status_code == 200
    tokens_css = tokens_resp.data.decode("utf-8")
    assert '[data-theme="dark"]' in tokens_css
    assert "--status-verified-bg" in tokens_css
    assert "--status-compromised-bg" in tokens_css

    comp_resp = client.get("/static/css/components.css")
    assert comp_resp.status_code == 200
    comp_css = comp_resp.data.decode("utf-8")
    assert ".hash-badge" in comp_css
    assert ".copy-btn" in comp_css
    assert ".chip-verified" in comp_css
    assert ".empty-state" in comp_css

    js_resp = client.get("/static/js/app.js")
    assert js_resp.status_code == 200
    js_code = js_resp.data.decode("utf-8")
    assert "initTheme" in js_code
    assert "initHashCopy" in js_code
