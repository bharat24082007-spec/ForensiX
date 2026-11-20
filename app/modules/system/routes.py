"""
ForensiX System Diagnostics, Backup, Health & Restoration Routes.
Exposes tool health checks, forensic executable status, asynchronous job polling,
and administrator disaster recovery operations.
"""

from __future__ import annotations

from pathlib import Path
from flask import Blueprint, render_template, request, jsonify, abort, flash, redirect, url_for, send_file, current_app
from flask_login import login_required, current_user

from app.security.rbac import role_required, case_member_required
from app.adapters.base import get_job_status
from app.modules.system.service import (
    get_system_tools_diagnostics,
    list_recent_tool_runs,
    get_tool_run_details,
    get_health_status,
    create_backup,
    list_backups,
    verify_backup_manifest,
    restore_backup,
    export_case_package,
)

system_bp = Blueprint("system", __name__, template_folder="../../templates")


# ------------------------------------------------------------------------------
# 1. Tools & Job Status
# ------------------------------------------------------------------------------

@system_bp.route("/system", methods=["GET"])
@login_required
def system_root():
    """Redirect /system to health monitoring."""
    return redirect(url_for("system.health_dashboard"))


@system_bp.route("/system/tools", methods=["GET"])
@role_required("Admin", "Lead")
def tools_diagnostics():
    """System forensic tool inventory, paths, version status, and execution audit history."""
    from app.modules.evidence.service import is_magic_available
    tools = get_system_tools_diagnostics()
    recent_runs = list_recent_tool_runs(limit=30)
    return render_template(
        "system/tools.html",
        active_nav="system",
        tools=tools,
        recent_runs=recent_runs,
        magic_available=is_magic_available(),
    )


@system_bp.route("/system/jobs/<int:job_id>/status", methods=["GET"])
@login_required
def job_status_api(job_id: int):
    """
    JSON polling endpoint for asynchronous background tool executions.
    Enforces per-case membership: users only see jobs belonging to cases they are members of.
    """
    job = get_tool_run_details(job_id)
    if not job:
        abort(404)

    # Check case access if user is not Admin
    if current_user.role != "Admin":
        from app.security.rbac import user_has_case_access
        if not user_has_case_access(current_user.id, current_user.role, job["case_id"]):
            abort(404)

    return jsonify(
        {
            "id": job["id"],
            "case_id": job["case_id"],
            "tool": job["tool"],
            "version": job["version"],
            "status": job["status"],
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "error": job["error"],
        }
    )


# ------------------------------------------------------------------------------
# 2. Health Monitoring
# ------------------------------------------------------------------------------

@system_bp.route("/system/health", methods=["GET"])
@role_required("Admin")
def health_dashboard():
    """System deep health diagnostics: DB integrity, disk quotas, vault synchronicity."""
    db_path = Path(current_app.config["DATABASE_PATH"])
    vault_dir = Path(current_app.config["VAULT_DIR"])
    data_dir = Path(current_app.config["DATA_DIR"])

    health_info = get_health_status(db_path, vault_dir, data_dir)
    return render_template(
        "system/health.html",
        active_nav="system",
        health=health_info,
    )


# ------------------------------------------------------------------------------
# 3. Backup Management
# ------------------------------------------------------------------------------

@system_bp.route("/system/backup", methods=["GET", "POST"])
@role_required("Admin")
def backup_management():
    """Manage encrypted full platform backups."""
    db_path = Path(current_app.config["DATABASE_PATH"])
    vault_dir = Path(current_app.config["VAULT_DIR"])
    backups_dir = Path(current_app.config["BACKUPS_DIR"])

    if request.method == "POST":
        try:
            backup_file = create_backup(db_path, vault_dir, backups_dir, current_user.id)
            flash(f"Encrypted backup '{backup_file.name}' created successfully.", "success")
        except Exception as e:
            flash(f"Backup failed: {e}", "error")
        return redirect(url_for("system.backup_management"))

    backups = list_backups(backups_dir)
    return render_template(
        "system/backup.html",
        active_nav="system",
        backups=backups,
    )


@system_bp.route("/system/backups/<filename>/download", methods=["GET"])
@role_required("Admin")
def download_backup(filename: str):
    """Download an encrypted backup file."""
    # Sanitize filename
    safe_name = Path(filename).name
    backups_dir = Path(current_app.config["BACKUPS_DIR"])
    target_path = backups_dir / safe_name
    if not target_path.is_file():
        abort(404)

    return send_file(target_path, as_attachment=True, download_name=safe_name, mimetype="application/octet-stream")


@system_bp.route("/system/restore", methods=["POST"])
@role_required("Admin")
def restore_management():
    """
    Restore data from an encrypted backup archive.
    Strictly requires typed confirmation 'CONFIRM RESTORE'.
    """
    confirm_text = request.form.get("confirm_text", "").strip()
    if confirm_text != "CONFIRM RESTORE":
        flash("Restoration rejected: You must type 'CONFIRM RESTORE' exactly to authorize data replacement.", "error")
        return redirect(url_for("system.backup_management"))

    uploaded_file = request.files.get("backup_file")
    selected_backup_name = request.form.get("existing_backup", "").strip()

    backups_dir = Path(current_app.config["BACKUPS_DIR"])
    db_path = Path(current_app.config["DATABASE_PATH"])
    vault_dir = Path(current_app.config["VAULT_DIR"])

    backup_path = None
    if uploaded_file and uploaded_file.filename:
        safe_name = Path(uploaded_file.filename).name
        target_path = backups_dir / f"uploaded_{safe_name}"
        uploaded_file.save(target_path)
        backup_path = target_path
    elif selected_backup_name:
        target_path = backups_dir / Path(selected_backup_name).name
        if target_path.is_file():
            backup_path = target_path

    if not backup_path:
        flash("No backup file selected or uploaded.", "error")
        return redirect(url_for("system.backup_management"))

    # Optional Master Key Recovery (C2)
    key_file = request.files.get("key_file")
    key_passphrase = request.form.get("key_passphrase", "").strip()
    if key_file and key_file.filename and key_passphrase:
        try:
            from app.security.crypto import decrypt_exported_master_key
            enc_key_bytes = key_file.read()
            recovered_key = decrypt_exported_master_key(enc_key_bytes, key_passphrase)
            master_key_path = Path(current_app.config["MASTER_KEY_PATH"])
            master_key_path.parent.mkdir(parents=True, exist_ok=True)
            master_key_path.write_bytes(recovered_key)
        except Exception as e:
            flash(f"Master key recovery failed: {e}", "error")
            return redirect(url_for("system.backup_management"))

    try:
        restore_backup(backup_path, db_path, vault_dir, current_user.id)
        flash("System data and vault restored successfully. Pre-flight integrity checks verified.", "success")
    except Exception as e:
        flash(f"Restoration aborted: {e}", "error")

    return redirect(url_for("system.backup_management"))


@system_bp.route("/system/keys/export", methods=["POST"])
@role_required("Admin")
def export_master_key_route():
    """Export encrypted master key payload using an Admin-supplied passphrase (Argon2id + AES-GCM) (C2)."""
    passphrase = request.form.get("passphrase", "").strip()
    if len(passphrase) < 12:
        flash("Master key export passphrase must be at least 12 characters.", "error")
        return redirect(url_for("system.backup_management"))

    try:
        from app.security.crypto import export_encrypted_master_key
        from io import BytesIO
        enc_payload = export_encrypted_master_key(passphrase)
        return send_file(
            BytesIO(enc_payload),
            as_attachment=True,
            download_name="forensix_master_key.enc",
            mimetype="application/octet-stream",
        )
    except Exception as e:
        flash(f"Master key export failed: {e}", "error")
        return redirect(url_for("system.backup_management"))


# ------------------------------------------------------------------------------
# 4. Portable Case Export
# ------------------------------------------------------------------------------

@system_bp.route("/cases/<int:case_id>/export", methods=["GET"])
@case_member_required
@role_required("Lead", "Admin")
def case_export(case_id: int):
    """Export self-contained ZIP archive of a case for external forensic or court review."""
    db_path = Path(current_app.config["DATABASE_PATH"])
    vault_dir = Path(current_app.config["VAULT_DIR"])
    work_dir = Path(current_app.config["WORK_DIR"])

    try:
        export_zip = export_case_package(case_id, db_path, vault_dir, work_dir, current_user.id)
        return send_file(
            export_zip,
            as_attachment=True,
            download_name=export_zip.name,
            mimetype="application/zip",
        )
    except Exception as e:
        flash(f"Case export failed: {e}", "error")
        return redirect(f"/cases/{case_id}")
