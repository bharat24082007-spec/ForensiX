"""
ForensiX Evidence Vault Routes.
Handles evidence upload, listing, detail inspection, metadata editing,
cryptographically verified downloads/views, and Legal-Hold-compliant withdrawal.
"""

from __future__ import annotations

import io
from pathlib import Path
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    abort,
    current_app,
)
from flask_login import login_required, current_user

from app.security.rbac import role_required, case_member_required
from app.modules.cases.service import get_case_details
from app.modules.evidence.service import (
    intake_evidence,
    verify_and_decrypt_evidence,
    list_evidence_for_case,
    get_evidence_details,
    get_evidence_custody_history,
    update_evidence_metadata,
    withdraw_evidence,
    DuplicateEvidenceError,
)

evidence_bp = Blueprint("evidence", __name__, template_folder="../../templates")


@evidence_bp.route("/cases/<int:case_id>/evidence", methods=["GET"])
@case_member_required
def evidence_list(case_id: int):
    """List all evidence vault items for the case."""
    case = get_case_details(case_id)
    if not case:
        abort(404)

    query_str = request.args.get("q", "").strip()
    tag_filter = request.args.get("tag", "").strip()
    status_filter = request.args.get("status", "All")

    evidence_items = list_evidence_for_case(
        case_id=case_id,
        query_str=query_str or None,
        tag_filter=tag_filter or None,
        status_filter=status_filter,
    )

    is_lead = (case["lead_user_id"] == current_user.id)
    can_upload = current_user.role in ("Admin", "Lead", "Analyst")

    return render_template(
        "evidence/list.html",
        active_nav="cases",
        active_tab="evidence",
        case=case,
        is_lead=is_lead,
        can_upload=can_upload,
        evidence_items=evidence_items,
        query_str=query_str,
        tag_filter=tag_filter,
        status_filter=status_filter,
    )


@evidence_bp.route("/cases/<int:case_id>/evidence/upload", methods=["GET", "POST"])
@role_required("Admin", "Lead", "Analyst")
@case_member_required
def evidence_upload(case_id: int):
    """Evidence intake endpoint. Computes SHA-256 and encrypts into vault."""
    case = get_case_details(case_id)
    if not case:
        abort(404)

    is_lead = (case["lead_user_id"] == current_user.id)

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file was uploaded.", "error")
            return redirect(request.url)

        uploaded_file = request.files["file"]
        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a valid evidence file.", "error")
            return redirect(request.url)

        tags = request.form.get("tags", "").strip()
        notes = request.form.get("notes", "").strip()
        source_type = request.form.get("source_type", "manual_upload").strip()

        vault_dir = Path(current_app.config["VAULT_DIR"])
        work_dir = Path(current_app.config["WORK_DIR"])

        try:
            evidence_id = intake_evidence(
                case_id=case_id,
                file_storage=uploaded_file,
                uploaded_by_user_id=current_user.id,
                vault_dir=vault_dir,
                work_dir=work_dir,
                tags=tags,
                notes=notes,
                source_type=source_type,
            )
            current_app.logger.info(
                f"User '{current_user.username}' uploaded evidence ID {evidence_id} to case ID {case_id}."
            )
            flash("Evidence safely stored and fingerprint verified.", "success")
            return redirect(url_for("evidence.evidence_detail", case_id=case_id, eid=evidence_id))
        except Exception as e:
            current_app.logger.error(f"Evidence intake error: {e}")
            flash(f"Intake failed: {e}", "error")

    return render_template(
        "evidence/upload.html",
        active_nav="cases",
        active_tab="evidence",
        case=case,
        is_lead=is_lead,
    )


@evidence_bp.route("/cases/<int:case_id>/evidence/<int:eid>", methods=["GET"])
@case_member_required
def evidence_detail(case_id: int, eid: int):
    """Evidence item detail inspection view."""
    case = get_case_details(case_id)
    if not case:
        abort(404)

    evidence = get_evidence_details(eid)
    if not evidence or evidence["case_id"] != case_id:
        abort(404)

    is_lead = (case["lead_user_id"] == current_user.id)
    can_edit = current_user.role in ("Admin", "Lead", "Analyst")
    custody_trail = get_evidence_custody_history(eid)

    return render_template(
        "evidence/detail.html",
        active_nav="cases",
        active_tab="evidence",
        case=case,
        evidence=evidence,
        is_lead=is_lead,
        can_edit=can_edit,
        custody_trail=custody_trail,
    )


@evidence_bp.route("/cases/<int:case_id>/evidence/<int:eid>/edit", methods=["POST"])
@role_required("Admin", "Lead", "Analyst")
@case_member_required
def evidence_edit(case_id: int, eid: int):
    """Update evidence tags and analyst notes."""
    tags = request.form.get("tags", "").strip()
    notes = request.form.get("notes", "").strip()

    try:
        update_evidence_metadata(eid, tags, notes, current_user.id)
        current_app.logger.info(f"User '{current_user.username}' updated metadata for evidence ID {eid}.")
        flash("Evidence metadata updated.", "success")
    except ValueError as e:
        flash(str(e), "error")

    return redirect(url_for("evidence.evidence_detail", case_id=case_id, eid=eid))


@evidence_bp.route("/cases/<int:case_id>/evidence/<int:eid>/download", methods=["GET"])
@case_member_required
def evidence_download(case_id: int, eid: int):
    """
    Download decrypted evidence.
    Integrity verification is strictly performed BEFORE serving the file.
    """
    vault_dir = Path(current_app.config["VAULT_DIR"])
    try:
        data, display_name, mime_type = verify_and_decrypt_evidence(
            evidence_id=eid,
            vault_dir=vault_dir,
            acting_user_id=current_user.id,
            action="DOWNLOAD",
        )
        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=display_name,
            mimetype=mime_type or "application/octet-stream",
        )
    except Exception as e:
        current_app.logger.error(f"Evidence download integrity error: {e}")
        flash(f"Download blocked: {e}", "error")
        return redirect(url_for("evidence.evidence_detail", case_id=case_id, eid=eid))


@evidence_bp.route("/cases/<int:case_id>/evidence/<int:eid>/view", methods=["GET"])
@case_member_required
def evidence_view(case_id: int, eid: int):
    """
    In-browser view of decrypted evidence after cryptographic integrity verification.
    """
    vault_dir = Path(current_app.config["VAULT_DIR"])
    try:
        data, display_name, mime_type = verify_and_decrypt_evidence(
            evidence_id=eid,
            vault_dir=vault_dir,
            acting_user_id=current_user.id,
            action="VIEW",
        )
        return send_file(
            io.BytesIO(data),
            as_attachment=False,
            download_name=display_name,
            mimetype=mime_type or "application/octet-stream",
        )
    except Exception as e:
        flash(f"View blocked: {e}", "error")
        return redirect(url_for("evidence.evidence_detail", case_id=case_id, eid=eid))


@evidence_bp.route("/cases/<int:case_id>/evidence/<int:eid>/withdraw", methods=["POST"])
@role_required("Admin", "Lead")
@case_member_required
def evidence_withdraw_route(case_id: int, eid: int):
    """Withdraw evidence from active investigation. Blocked under Legal Hold."""
    reason = request.form.get("reason", "").strip()
    try:
        withdraw_evidence(eid, reason, current_user.id)
        current_app.logger.info(f"Lead '{current_user.username}' withdrew evidence ID {eid}.")
        flash("Evidence item successfully withdrawn.", "warning")
    except (ValueError, PermissionError) as e:
        flash(str(e), "error")

    return redirect(url_for("evidence.evidence_detail", case_id=case_id, eid=eid))
