"""
Tests for Section S6: Tool Adapter Framework.
Verifies standardized subprocess execution, hard timeout kills, stdout output caps,
ephemeral decrypted working copy isolation, pre/post integrity hashing, secure wiping,
missing tool graceful degradation, and asynchronous job tracking.
"""

from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path
import pytest
from werkzeug.datastructures import FileStorage

from app import create_app
from app.db import execute_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.evidence.service import intake_evidence
from app.adapters.registry import (
    register_tool,
    get_tool_info,
    is_tool_available,
    list_all_tools,
)
from app.adapters.base import run_tool, submit_async_tool_job, get_job_status


@pytest.fixture
def adapter_app(tmp_path: Path):
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


def test_registry_tool_registration_and_detection():
    """Verify registry probes executable paths and extracts version strings."""
    # Register current Python binary as a test tool
    info = register_tool(
        tool_key="test_py",
        name="Test Python Interpreter",
        configured_path=sys.executable,
        description="Python runtime test adapter",
        version_args=["--version"],
    )

    assert info["available"] is True
    assert info["resolved_path"] is not None
    assert "Python" in (info["version"] or "")
    assert is_tool_available("test_py") is True

    # Register missing tool
    missing = register_tool(
        tool_key="nonexistent_binary_xyz",
        name="Missing Tool",
        configured_path="completely_fake_nonexistent_executable_12345",
        description="Fictitious missing tool",
    )
    assert missing["available"] is False
    assert is_tool_available("nonexistent_binary_xyz") is False
    assert "not found" in missing["error"].lower()


def test_missing_tool_gracefully_degrades(adapter_app):
    """Verify invoking a missing tool returns an unavailable result without crashing."""
    with adapter_app.app_context():
        lead_id = create_user("Lead User", "lead_adapt1", "Lead", "Pass123456789!")
        case_id = create_case("Adapter Test Case", "Tool testing", "Medium", lead_id)

        res = run_tool(
            tool_key="nonexistent_binary_xyz",
            args=["--help"],
            case_id=case_id,
            acting_user_id=lead_id,
        )

        assert res["status"] == "unavailable"
        assert res["returncode"] is None
        assert "not available" in res["error"].lower()

        # Check tool_runs table recorded the failed attempt
        run_row = query_db("SELECT status, error FROM tool_runs WHERE id = ?", (res["run_id"],), one=True)
        assert run_row["status"] == "failed"
        assert "not available" in run_row["error"].lower()


def test_run_tool_harmless_command_success(adapter_app):
    """Verify running a harmless command succeeds, captures stdout, and writes custody log."""
    with adapter_app.app_context():
        lead_id = create_user("Lead User", "lead_adapt2", "Lead", "Pass123456789!")
        case_id = create_case("Harmless Tool Case", "Testing clean execution", "Low", lead_id)

        res = run_tool(
            tool_key="test_py",
            args=["-c", "print('FORENSIX_PARSER_SUCCESS')"],
            case_id=case_id,
            custom_executable=sys.executable,
            acting_user_id=lead_id,
        )

        assert res["status"] == "done"
        assert res["returncode"] == 0
        assert "FORENSIX_PARSER_SUCCESS" in res["stdout"]

        # Check tool_runs table
        run_row = query_db("SELECT status, tool FROM tool_runs WHERE id = ?", (res["run_id"],), one=True)
        assert run_row["status"] == "done"
        assert run_row["tool"] == "test_py"

        # Check custody log
        custody_row = query_db(
            "SELECT action, detail_json FROM custody_log WHERE case_id = ? AND action = 'ANALYSIS_RUN'",
            (case_id,),
            one=True,
        )
        assert custody_row is not None
        assert "stdout" not in custody_row["detail_json"]  # No evidence output in custody log
        assert custody_row["action"] == "ANALYSIS_RUN"


def test_run_tool_timeout_kills_sleeping_process(adapter_app):
    """Verify execution timeout forcibly terminates long-running or hung subprocesses."""
    with adapter_app.app_context():
        lead_id = create_user("Lead User", "lead_adapt3", "Lead", "Pass123456789!")
        case_id = create_case("Timeout Test Case", "Subprocess kill testing", "High", lead_id)

        # Attempt to sleep for 10 seconds with a 1-second timeout cap
        res = run_tool(
            tool_key="test_py",
            args=["-c", "import time; time.sleep(10)"],
            case_id=case_id,
            timeout=1,
            custom_executable=sys.executable,
            acting_user_id=lead_id,
        )

        assert res["status"] == "failed"
        assert "timed out" in (res["error"] or "").lower()
        assert res["duration_sec"] < 5.0  # Killed in under 5 seconds, not 10

        run_row = query_db("SELECT status, error FROM tool_runs WHERE id = ?", (res["run_id"],), one=True)
        assert run_row["status"] == "failed"
        assert "timed out" in run_row["error"].lower()


def test_run_tool_output_cap_truncates_and_terminates(adapter_app):
    """Verify output cap stops memory exhaustion from high-volume tool stdout."""
    with adapter_app.app_context():
        lead_id = create_user("Lead User", "lead_adapt4", "Lead", "Pass123456789!")
        case_id = create_case("Output Cap Case", "Output limit testing", "High", lead_id)

        # Emit 50,000 bytes with a 1,024 byte cap
        res = run_tool(
            tool_key="test_py",
            args=["-c", "import sys; sys.stdout.write('A' * 50000); sys.stdout.flush()"],
            case_id=case_id,
            max_output_bytes=1024,
            custom_executable=sys.executable,
            acting_user_id=lead_id,
        )

        assert res["status"] == "failed"
        assert "cap exceeded" in (res["error"] or "").lower()
        assert len(res["stdout"]) <= 1024


def test_working_copy_decryption_integrity_and_wipe(adapter_app):
    """Verify decrypted evidence is verified before/after execution and wiped from disk in finally block."""
    with adapter_app.app_context():
        vault_dir = Path(adapter_app.config["VAULT_DIR"])
        work_dir = Path(adapter_app.config["WORK_DIR"])

        lead_id = create_user("Lead User", "lead_adapt5", "Lead", "Pass123456789!")
        case_id = create_case("Wipe Test Case", "Working copy lifecycle", "Critical", lead_id)

        # Ingest evidence
        payload = b"CRITICAL FORENSIC EVIDENCE PACKET FOR ADAPTER VERIFICATION"
        storage = FileStorage(stream=io.BytesIO(payload), filename="evidence.bin", content_type="application/octet-stream")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="Memory Dump",
            uploaded_by_user_id=lead_id,
        )

        # Python script that reads the decrypted file and verifies its contents
        script = "import sys, pathlib; path = sys.argv[1]; print('READ_BYTES:', len(pathlib.Path(path).read_bytes()))"

        res = run_tool(
            tool_key="test_py",
            args=["-c", script, "{input_file}"],
            case_id=case_id,
            input_evidence_id=ev_id,
            custom_executable=sys.executable,
            acting_user_id=lead_id,
            app=adapter_app,
        )

        assert res["status"] == "done"
        assert f"READ_BYTES: {len(payload)}" in res["stdout"]

        # Crucial CIA Confidentiality Check:
        # After run_tool completes, the working copy directory in data/work/ MUST NOT EXIST
        work_entries = list(work_dir.glob("job_*"))
        assert len(work_entries) == 0, f"Working folder was not wiped! Remnants found: {work_entries}"


def test_async_job_submission_and_status_api(adapter_app):
    """Verify in-process thread pool job submission and JSON status polling."""
    client = adapter_app.test_client()

    with adapter_app.app_context():
        lead_id = create_user("Lead Async", "lead_async", "Lead", "Pass123456789!")
        outsider_id = create_user("Outsider", "outsider_async", "Analyst", "Pass123456789!")
        case_id = create_case("Async Job Case", "Testing background executor", "Medium", lead_id)

        # Submit async job
        job_id = submit_async_tool_job(
            app=adapter_app,
            tool_key="test_py",
            args=["-c", "import time; time.sleep(0.3); print('ASYNC_JOB_COMPLETE')"],
            case_id=case_id,
            custom_executable=sys.executable,
            acting_user_id=lead_id,
        )

        assert job_id > 0
        status_info = get_job_status(job_id)
        assert status_info["status"] in ("queued", "running")

    # 1. Lead polls status API -> 200 OK
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)

    # Allow worker thread to finish
    time.sleep(0.8)

    resp = client.get(f"/system/jobs/{job_id}/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == job_id
    assert data["status"] == "done"
    assert data["finished_at"] is not None

    # 2. Outsider attempts to poll status -> 404 (isolation enforced)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)

    resp_out = client.get(f"/system/jobs/{job_id}/status")
    assert resp_out.status_code == 404


def test_system_tools_page_renders_diagnostics(adapter_app):
    """Verify /system/tools renders registered forensic tool cards and safeguards."""
    client = adapter_app.test_client()

    with adapter_app.app_context():
        admin_id = create_user("Admin User", "admin_tools", "Admin", "Pass123456789!")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)

    resp = client.get("/system/tools")
    assert resp.status_code == 200
    assert b"External Tool Adapters" in resp.data
    assert b"Wireshark TShark" in resp.data
    assert b"ExifTool" in resp.data
    assert b"Subprocess Security &amp; Forensic Safeguards" in resp.data
