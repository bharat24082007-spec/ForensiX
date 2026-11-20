"""
ForensiX Forensic Report Generator Routes.
Handles report generation, signing, download, and public verification.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required

from app.db import execute_db, query_db
from app.modules.cases.service import list_cases_for_user
from app.modules.custody.service import append as custody_append
from app.modules.reports.service import (
    generate_forensic_report,
    get_report_path,
    list_case_reports,
    sign_report,
    verify_report_signature,
)
from app.security.rbac import case_member_required, role_required

reports_bp = Blueprint("reports", __name__, template_folder="../../templates")


# ---------------------------------------------------------------------------
# GET /reports — global list of reports across accessible cases (A1)
# ---------------------------------------------------------------------------

@reports_bp.route("/reports", methods=["GET"])
@login_required
def all_reports_view():
    """Global reports list across cases accessible to the user (A1)."""
    cases = list_cases_for_user(current_user.id, current_user.role)
    case_ids = [c["id"] for c in cases]
    if case_ids:
        placeholders = ",".join("?" * len(case_ids))
        sql = f"""
            SELECT r.id, r.case_id, r.file_name, r.sha256, r.signature, r.signed_by,
                   r.chain_head_hash, r.created_at,
                   c.case_no, c.title AS case_title,
                   u.name AS signer_name
            FROM reports r
            JOIN cases c ON r.case_id = c.id
            LEFT JOIN users u ON r.signed_by = u.id
            WHERE r.case_id IN ({placeholders})
            ORDER BY r.id DESC
        """
        reports = query_db(sql, tuple(case_ids))
    else:
        reports = []

    return render_template(
        "reports/report_list.html",
        case=None,
        reports=[dict(r) for r in reports],
        is_lead=False,
        active_nav="reports",
    )


# ---------------------------------------------------------------------------
# GET /cases/<case_id>/reports — list reports
# ---------------------------------------------------------------------------

@reports_bp.route("/cases/<int:case_id>/reports", methods=["GET"])
@case_member_required
def report_list(case_id: int):
    case = g.case
    reports = list_case_reports(case_id)

    # Enrich case with lead name for template
    lead = query_db("SELECT name, username FROM users WHERE id = ?", (case["lead_user_id"],), one=True)
    case["lead_name"] = lead["name"] if lead else "Unknown"
    case["lead_username"] = lead["username"] if lead else "unknown"

    is_lead = (case["lead_user_id"] == current_user.id)
    return render_template(
        "reports/report_list.html",
        case=case,
        reports=reports,
        is_lead=is_lead,
        active_tab="reports",
    )


# ---------------------------------------------------------------------------
# POST /cases/<case_id>/reports/generate — generate report
# ---------------------------------------------------------------------------

@reports_bp.route("/cases/<int:case_id>/reports/generate", methods=["POST"])
@case_member_required
@role_required("Admin", "Lead", "Analyst")
def report_generate(case_id: int):
    reports_dir = Path(current_app.config["REPORTS_DIR"])
    try:
        pdf_path = generate_forensic_report(case_id, current_user.id, reports_dir)
    except Exception as e:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"error": f"Report generation failed: {e}"}), 500
        flash(f"Report generation failed: {e}", "error")
        return redirect(url_for("reports.report_list", case_id=case_id))

    # Compute SHA-256 of generated PDF bytes
    pdf_bytes = pdf_path.read_bytes()
    sha256_hash = hashlib.sha256(pdf_bytes).hexdigest()

    # Get chain head hash
    from app.modules.custody.service import verify_chain
    chain_res = verify_chain(case_id)
    chain_head = chain_res.get("head_hash", "0" * 64)

    # Automatically sign the report bytes with Ed25519 keypair
    from app.modules.reports.service import _ensure_user_keypair
    from app.security.crypto import load_ed25519_private_key
    _ensure_user_keypair(current_user.id)

    signature_hex = ""
    user_row = query_db(
        "SELECT sign_priv_key_enc FROM users WHERE id = ?",
        (current_user.id,),
        one=True,
    )
    if user_row and user_row["sign_priv_key_enc"]:
        try:
            priv_key = load_ed25519_private_key(user_row["sign_priv_key_enc"])
            sig_bytes = priv_key.sign(bytes.fromhex(sha256_hash))
            signature_hex = sig_bytes.hex()
        except Exception:
            signature_hex = ""

    # Store report record in database with hash and Ed25519 signature
    report_id = execute_db(
        """
        INSERT INTO reports (case_id, file_name, sha256, signature, signed_by, chain_head_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (case_id, pdf_path.name, sha256_hash, signature_hex, current_user.id, chain_head),
    )

    # Detached signature file (.sig)
    if signature_hex:
        sig_path = reports_dir / f"{pdf_path.name}.sig"
        try:
            sig_path.write_text(signature_hex, encoding="utf-8")
        except Exception:
            pass

    # Custody entry (REPORT_GENERATED)
    custody_append(
        case_id=case_id,
        evidence_id=None,
        user_id=current_user.id,
        action="REPORT_GENERATED",
        detail={
            "report_id": report_id,
            "file_name": pdf_path.name,
            "sha256": sha256_hash,
            "signature": signature_hex,
        },
    )

    case_row = query_db("SELECT case_no FROM cases WHERE id = ?", (case_id,), one=True)
    case_no = case_row["case_no"] if case_row else f"CASE-{case_id}"
    download_filename = f"ForensiX_{case_no}_Report.pdf"

    # Return PDF file as attachment so one click downloads it automatically
    resp = send_file(
        pdf_path,
        as_attachment=True,
        download_name=download_filename,
        mimetype="application/pdf",
    )
    resp.headers["X-Report-Id"] = str(report_id)
    resp.headers["X-Report-Sha256"] = sha256_hash
    resp.headers["Access-Control-Expose-Headers"] = "X-Report-Id, X-Report-Sha256, Content-Disposition"
    return resp


# ---------------------------------------------------------------------------
# POST /cases/<case_id>/reports/<rid>/sign — sign report (Lead only)
# ---------------------------------------------------------------------------

@reports_bp.route("/cases/<int:case_id>/reports/<int:rid>/sign", methods=["POST"])
@case_member_required
@role_required("Lead")
def report_sign(case_id: int, rid: int):
    password = request.form.get("password", "")
    if not password:
        flash("Password required for signing.", "error")
        return redirect(url_for("reports.report_list", case_id=case_id))

    keys_dir = Path(current_app.config["KEYS_DIR"])
    reports_dir = Path(current_app.config["REPORTS_DIR"])
    success = sign_report(rid, current_user.id, password, keys_dir, reports_dir=reports_dir)
    if success:
        flash("Report signed successfully.", "success")
    else:
        flash("Signing failed: invalid password or report not found.", "error")

    return redirect(url_for("reports.report_list", case_id=case_id))


# ---------------------------------------------------------------------------
# GET /reports/<rid>/download — download PDF
# ---------------------------------------------------------------------------

@reports_bp.route("/reports/<int:rid>/download", methods=["GET"])
@login_required
def report_download(rid: int):
    report_row = query_db(
        "SELECT case_id, file_name FROM reports WHERE id = ?",
        (rid,),
        one=True,
    )
    if not report_row:
        abort(404)

    # Verify case membership
    case_id = report_row["case_id"]
    from app.security.rbac import user_has_case_access
    if not user_has_case_access(current_user.id, current_user.role, case_id):
        abort(404)

    reports_dir = Path(current_app.config["REPORTS_DIR"])
    pdf_path = get_report_path(rid, reports_dir)
    if not pdf_path:
        abort(404)

    # Custody log download event
    custody_append(
        case_id=case_id,
        evidence_id=None,
        user_id=current_user.id,
        action="REPORT_DOWNLOAD",
        detail={"report_id": rid, "file_name": report_row["file_name"]},
    )

    return send_file(pdf_path, as_attachment=True, download_name=report_row["file_name"], mimetype="application/pdf")


@reports_bp.route("/reports/<int:rid>/sig", methods=["GET"])
@login_required
def report_download_sig(rid: int):
    """Download detached Ed25519 signature file (.sig) for external cryptographic verification."""
    report_row = query_db(
        "SELECT case_id, file_name, signature FROM reports WHERE id = ?",
        (rid,),
        one=True,
    )
    if not report_row or not report_row["signature"]:
        abort(404)

    case_id = report_row["case_id"]
    from app.security.rbac import user_has_case_access
    if not user_has_case_access(current_user.id, current_user.role, case_id):
        abort(404)

    from io import BytesIO
    sig_filename = f"{report_row['file_name']}.sig"
    return send_file(
        BytesIO(report_row["signature"].encode("utf-8")),
        as_attachment=True,
        download_name=sig_filename,
        mimetype="text/plain",
    )


# ---------------------------------------------------------------------------
# GET/POST /verify-report — public or authenticated report verification
# ---------------------------------------------------------------------------

@reports_bp.route("/verify-report", methods=["GET", "POST"])
def verify_report_view():
    result = None
    if request.method == "POST":
        uploaded = request.files.get("report_file")
        report_id_str = request.form.get("report_id", "").strip()
        report_hash = request.form.get("report_hash", "").strip()

        pdf_bytes = uploaded.read() if uploaded and uploaded.filename else None
        report_id = int(report_id_str) if report_id_str.isdigit() else None

        if not pdf_bytes and not report_hash and not report_id:
            flash("Please upload a PDF report or enter a Report ID / SHA-256 hash.", "error")
        else:
            try:
                result = verify_report_signature(
                    pdf_bytes=pdf_bytes,
                    report_id=report_id,
                    report_hash=report_hash,
                )
            except Exception as e:
                flash(f"Verification error: {e}", "error")

    return render_template("reports/report_verify.html", result=result, active_nav="verify_report")
