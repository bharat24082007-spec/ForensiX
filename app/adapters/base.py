"""
ForensiX Standardized Tool Adapter Engine.
Provides a secure, uniform execution wrapper for all external forensic tools and parsers.
Enforces:
- Hard ban on shell=True (always parameterized list[str])
- Hard subprocess timeouts and stdout output size caps (kills overrun processes)
- Ephemeral decrypted working copy isolation in data/work/<job_id>/
- Pre- and post-execution SHA-256 integrity verification (working copy must not be modified)
- Secure byte-wiping and removal of working copies in a finally block
- Immutable custody_log auditing (ANALYSIS_RUN) and tool_runs status tracking
- In-process ThreadPoolExecutor (max 2 workers) for asynchronous job execution
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import current_app, Flask

from app.db import query_db, execute_db, get_db
from app.modules.custody.service import append as custody_append
from app.security.crypto import decrypt_stream_aes_gcm_chunked
from app.adapters.registry import get_tool_info, is_tool_available, get_tool_executable

logger = logging.getLogger("forensix")

# Bounded in-process worker pool for background analysis jobs (max 2 concurrent workers)
_TOOL_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="forensix_tool_worker")


def _secure_wipe_file(file_path: Path) -> None:
    """Overwrites file bytes with zeros before unlinking to prevent data remnants."""
    try:
        if file_path.is_file():
            # Ensure file is writable on Windows
            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            size = file_path.stat().st_size
            if size > 0:
                with open(file_path, "wb") as f:
                    # Write zeroes in 64KB blocks
                    remaining = size
                    chunk = b"\x00" * min(65536, remaining)
                    while remaining > 0:
                        write_len = min(len(chunk), remaining)
                        f.write(chunk[:write_len])
                        remaining -= write_len
                    f.flush()
            file_path.unlink(missing_ok=True)
    except Exception as e:
        logger.warning(f"Error securely wiping file {file_path}: {e}")
        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass


def _secure_wipe_directory(dir_path: Path) -> None:
    """Recursively wipes and removes a temporary job directory."""
    try:
        if dir_path.is_dir():
            for root, dirs, files in os.walk(dir_path, topdown=False):
                for f in files:
                    _secure_wipe_file(Path(root) / f)
                for d in dirs:
                    try:
                        (Path(root) / d).rmdir()
                    except Exception:
                        pass
            try:
                dir_path.rmdir()
            except Exception:
                shutil.rmtree(dir_path, ignore_errors=True)
    except Exception as e:
        logger.warning(f"Error cleaning directory {dir_path}: {e}")


def _compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 checksum of a local file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def run_tool(
    tool_key: str,
    args: List[str],
    case_id: int,
    input_evidence_id: Optional[int] = None,
    timeout: int = 30,
    max_output_bytes: int = 10 * 1024 * 1024,  # 10 MB default cap
    acting_user_id: Optional[int] = None,
    custom_executable: Optional[str] = None,
    existing_run_id: Optional[int] = None,
    app: Optional[Flask] = None,
) -> Dict[str, Any]:
    """
    Synchronously execute a forensic tool or parser subprocess with strict containment.
    
    Returns:
      {
        "status": "done" | "failed" | "unavailable",
        "returncode": int or None,
        "stdout": str or bytes,
        "stderr": str or bytes,
        "tool": str,
        "version": str,
        "duration_sec": float,
        "error": str or None,
        "run_id": int,
      }
    """
    start_time = time.time()
    now_utc = datetime.now(timezone.utc).isoformat()

    # 1. Resolve Tool Executable & Version
    executable = custom_executable
    tool_version = "Unknown"

    if not executable:
        tool_info = get_tool_info(tool_key)
        if not tool_info or not tool_info.get("available"):
            err_msg = f"Tool '{tool_key}' is not available or not installed on this system."
            logger.warning(err_msg)
            # Record failed/unavailable run in DB if case_id is valid
            run_id = existing_run_id or execute_db(
                """
                INSERT INTO tool_runs (case_id, evidence_id, tool, version, args_json, input_sha256, status, started_at, finished_at, error)
                VALUES (?, ?, ?, ?, ?, ?, 'failed', ?, ?, ?)
                """,
                (case_id, input_evidence_id, tool_key, "None", json.dumps(args), "N/A", now_utc, now_utc, err_msg),
            )
            return {
                "status": "unavailable",
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "tool": tool_key,
                "version": "None",
                "duration_sec": 0.0,
                "error": err_msg,
                "run_id": run_id,
            }
        executable = tool_info["resolved_path"]
        tool_version = tool_info.get("version", "Unknown")

    # 2. Register or fetch initial tool_runs entry
    input_sha256 = "N/A"
    evidence_row = None
    if input_evidence_id:
        evidence_row = query_db(
            "SELECT id, case_id, display_name, stored_name, sha256 FROM evidence WHERE id = ?",
            (input_evidence_id,),
            one=True,
        )
        if evidence_row:
            input_sha256 = evidence_row["sha256"]

    if existing_run_id:
        run_id = existing_run_id
        execute_db(
            "UPDATE tool_runs SET status = 'running', started_at = ? WHERE id = ?",
            (now_utc, run_id),
        )
    else:
        run_id = execute_db(
            """
            INSERT INTO tool_runs (case_id, evidence_id, tool, version, args_json, input_sha256, status, started_at)
            VALUES (?, ?, ?, ?, ?, ?, 'running', ?)
            """,
            (case_id, input_evidence_id, tool_key, tool_version, json.dumps(args), input_sha256, now_utc),
        )

    # 3. Setup Ephemeral Working Directory
    app_obj = app or current_app._get_current_object()
    work_base = Path(app_obj.config["WORK_DIR"])
    job_work_dir = work_base / f"job_{run_id}_{int(time.time())}"
    job_work_dir.mkdir(parents=True, exist_ok=True)

    working_evidence_path: Optional[Path] = None
    pre_execution_hash: Optional[str] = None
    exec_args = list(args)

    try:
        # 4. Decrypt evidence to working directory if required
        if evidence_row:
            vault_file = Path(app_obj.config["VAULT_DIR"]) / evidence_row["stored_name"]
            if not vault_file.is_file():
                raise FileNotFoundError(f"Encrypted vault file missing for evidence ID {input_evidence_id}.")

            working_evidence_path = job_work_dir / f"work_{evidence_row['id']}_{evidence_row['display_name']}"
            with open(working_evidence_path, "wb") as f_out:
                for chunk in decrypt_stream_aes_gcm_chunked(vault_file):
                    f_out.write(chunk)

            # Integrity check BEFORE execution
            pre_execution_hash = _compute_file_sha256(working_evidence_path)
            if pre_execution_hash != evidence_row["sha256"]:
                raise ValueError(
                    f"Intake fingerprint mismatch on decrypted working copy: {pre_execution_hash} != {evidence_row['sha256']}"
                )

            # Substitute placeholder or append working copy path
            if "{input_file}" in exec_args:
                exec_args = [str(working_evidence_path) if a == "{input_file}" else a for a in exec_args]
            elif not any(str(working_evidence_path) in a for a in exec_args):
                exec_args.append(str(working_evidence_path))

        # 5. Execute Subprocess (Strictly shell=False)
        cmd_list = [executable] + exec_args
        logger.info(f"Executing tool '{tool_key}' (Run #{run_id}): {cmd_list[0]} with {len(exec_args)} arguments.")

        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,  # Hard security ban on shell=True
            cwd=str(job_work_dir),
        )

        stdout_chunks: List[bytes] = []
        stderr_chunks: List[bytes] = []
        total_stdout_len = 0
        error_msg: Optional[str] = None
        timed_out = False
        cap_exceeded = False

        def _read_stdout():
            nonlocal total_stdout_len, cap_exceeded, error_msg
            try:
                while True:
                    chunk = proc.stdout.read(8192)
                    if not chunk:
                        break
                    stdout_chunks.append(chunk)
                    total_stdout_len += len(chunk)
                    if total_stdout_len > max_output_bytes:
                        cap_exceeded = True
                        error_msg = f"Output size cap exceeded ({total_stdout_len} bytes > {max_output_bytes} cap). Terminated."
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        break
            except Exception:
                pass

        def _read_stderr():
            try:
                while True:
                    chunk = proc.stderr.read(8192)
                    if not chunk:
                        break
                    stderr_chunks.append(chunk)
            except Exception:
                pass

        t_out = threading.Thread(target=_read_stdout, daemon=True)
        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_out.start()
        t_err.start()

        start_wait = time.time()
        while proc.poll() is None:
            if time.time() - start_wait > timeout:
                timed_out = True
                error_msg = f"Tool execution timed out after {timeout} seconds."
                try:
                    proc.kill()
                except Exception:
                    pass
                break
            time.sleep(0.05)

        proc.wait()
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)

        raw_stdout = b"".join(stdout_chunks)
        raw_stderr = b"".join(stderr_chunks)

        if cap_exceeded:
            raw_stdout = raw_stdout[:max_output_bytes]

        returncode = proc.returncode

        # 6. Verify Working Copy Integrity AFTER Run
        if working_evidence_path and working_evidence_path.is_file():
            post_execution_hash = _compute_file_sha256(working_evidence_path)
            if post_execution_hash != pre_execution_hash:
                error_msg = (error_msg or "") + " [INTEGRITY ALERT: Tool modified working copy during analysis!]"
                logger.critical(
                    f"Tool '{tool_key}' modified working file {working_evidence_path}! Hash changed from {pre_execution_hash} to {post_execution_hash}."
                )

        duration = round(time.time() - start_time, 3)
        final_status = "done" if (returncode == 0 and not timed_out and not cap_exceeded) else "failed"
        finish_now = datetime.now(timezone.utc).isoformat()

        # Decode output safely as text (lossy UTF-8)
        stdout_text = raw_stdout.decode("utf-8", errors="replace")
        stderr_text = raw_stderr.decode("utf-8", errors="replace")

        # 7. Update tool_runs in Database
        execute_db(
            """
            UPDATE tool_runs
            SET status = ?, finished_at = ?, error = ?
            WHERE id = ?
            """,
            (final_status, finish_now, error_msg or (stderr_text[:500] if returncode != 0 else None), run_id),
        )

        # 8. Log ANALYSIS_RUN in Custody Chain
        custody_append(
            case_id=case_id,
            evidence_id=input_evidence_id,
            user_id=acting_user_id,
            action="ANALYSIS_RUN",
            detail={
                "tool": tool_key,
                "version": tool_version,
                "args": exec_args,
                "input_sha256": input_sha256,
                "returncode": returncode,
                "status": final_status,
                "duration_sec": duration,
                "run_id": run_id,
            },
            timestamp_utc=finish_now,
        )

        return {
            "status": final_status,
            "returncode": returncode,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "tool": tool_key,
            "version": tool_version,
            "duration_sec": duration,
            "error": error_msg,
            "run_id": run_id,
        }

    except Exception as e:
        duration = round(time.time() - start_time, 3)
        finish_now = datetime.now(timezone.utc).isoformat()
        err_str = str(e)
        logger.error(f"Execution error in run_tool ({tool_key}): {err_str}", exc_info=True)

        execute_db(
            """
            UPDATE tool_runs
            SET status = 'failed', finished_at = ?, error = ?
            WHERE id = ?
            """,
            (finish_now, err_str, run_id),
        )

        custody_append(
            case_id=case_id,
            evidence_id=input_evidence_id,
            user_id=acting_user_id,
            action="ANALYSIS_RUN",
            detail={
                "tool": tool_key,
                "version": tool_version,
                "args": exec_args,
                "input_sha256": input_sha256,
                "status": "failed",
                "error": err_str,
                "run_id": run_id,
            },
            timestamp_utc=finish_now,
        )

        return {
            "status": "failed",
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "tool": tool_key,
            "version": tool_version,
            "duration_sec": duration,
            "error": err_str,
            "run_id": run_id,
        }

    finally:
        # 9. Securely wipe ephemeral working copy and directory
        _secure_wipe_directory(job_work_dir)


def submit_async_tool_job(
    app: Flask,
    tool_key: str,
    args: List[str],
    case_id: int,
    input_evidence_id: Optional[int] = None,
    timeout: int = 30,
    max_output_bytes: int = 10 * 1024 * 1024,
    acting_user_id: Optional[int] = None,
    custom_executable: Optional[str] = None,
    callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> int:
    """
    Queue an external tool analysis job in the in-process ThreadPool.
    Returns the initial tool_runs ID with 'queued' status.
    """
    now_utc = datetime.now(timezone.utc).isoformat()
    tool_info = get_tool_info(tool_key)
    version = tool_info.get("version", "Pending") if tool_info else "Custom"
    input_sha256 = "N/A"

    if input_evidence_id:
        ev = query_db("SELECT sha256 FROM evidence WHERE id = ?", (input_evidence_id,), one=True)
        if ev:
            input_sha256 = ev["sha256"]

    run_id = execute_db(
        """
        INSERT INTO tool_runs (case_id, evidence_id, tool, version, args_json, input_sha256, status, started_at)
        VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)
        """,
        (case_id, input_evidence_id, tool_key, version, json.dumps(args), input_sha256, now_utc),
    )

    def _worker():
        with app.app_context():
            res = run_tool(
                tool_key=tool_key,
                args=args,
                case_id=case_id,
                input_evidence_id=input_evidence_id,
                timeout=timeout,
                max_output_bytes=max_output_bytes,
                acting_user_id=acting_user_id,
                custom_executable=custom_executable,
                existing_run_id=run_id,
                app=app,
            )
            if callback:
                try:
                    callback(res)
                except Exception as cb_err:
                    logger.error(f"Callback error after tool run #{run_id}: {cb_err}")

    _TOOL_EXECUTOR.submit(_worker)
    return run_id


def get_job_status(job_id: int) -> Optional[Dict[str, Any]]:
    """Query current execution state and metadata for a tool run."""
    row = query_db(
        """
        SELECT id, case_id, evidence_id, tool, version, args_json,
               input_sha256, status, started_at, finished_at, error
        FROM tool_runs WHERE id = ?
        """,
        (job_id,),
        one=True,
    )
    if not row:
        return None
    res = dict(row)
    try:
        res["args"] = json.loads(res["args_json"])
    except Exception:
        res["args"] = []
    return res
