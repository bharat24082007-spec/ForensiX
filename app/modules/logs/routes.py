"""
ForensiX Log Analyser Routes.
Provides routes to inspect, configure, analyze, and export log evidence,
including SSH auth.log and Apache/Nginx web access logs.
"""

from __future__ import annotations

import csv
import io
import json
from flask import (
    Blueprint,
    Response,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
    jsonify,
)
from flask_login import login_required, current_user

from app.security.rbac import case_member_required
from app.modules.cases.service import get_case_details
from app.modules.evidence.service import get_evidence_details
from app.modules.logs.service import (
    analyze_log_evidence,
    get_stored_log_summary,
    get_raw_log_lines_by_numbers,
)

logs_bp = Blueprint("logs", __name__, template_folder="../../templates")


@logs_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/logs", methods=["GET"])
@case_member_required
def view_logs(case_id: int, evidence_id: int):
    """View log analysis findings, timeline events, and line viewer."""
    case = get_case_details(case_id)
    ev = get_evidence_details(evidence_id)
    if not case or not ev or ev["case_id"] != case_id:
        abort(404)

    is_lead = (case["lead_user_id"] == current_user.id)
    can_analyze = current_user.role in ("Admin", "Lead", "Analyst", "admin", "lead", "analyst")

    stored = get_stored_log_summary(case_id, evidence_id)

    # Detect default format guess from filename
    filename_lower = ev["display_name"].lower()
    default_format = "auth.log"
    if "access" in filename_lower or "nginx" in filename_lower or "apache" in filename_lower or "web" in filename_lower:
        default_format = "web.log"

    force_refresh = request.args.get("refresh") == "1"
    analysis_data = None

    if force_refresh or (not stored["events"] and not stored["findings"]):
        try:
            analysis_data = analyze_log_evidence(
                case_id=case_id,
                evidence_id=evidence_id,
                log_format=default_format,
                year_assumption=2026,
                tz_offset_hours=0,
                acting_user_id=current_user.id,
            )
            stored = get_stored_log_summary(case_id, evidence_id)
        except Exception as e:
            flash(f"Log analysis warning: {e}", "warning")

    return render_template(
        "logs/detail.html",
        active_nav="cases",
        active_tab="evidence",
        case=case,
        evidence=ev,
        is_lead=is_lead,
        can_analyze=can_analyze,
        analysis=analysis_data,
        events=stored["events"],
        findings=stored["findings"],
        iocs=stored["iocs"],
        default_format=default_format,
    )


@logs_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/logs/analyze", methods=["POST"])
@case_member_required
def trigger_analysis(case_id: int, evidence_id: int):
    """Trigger log analysis with analyst-supplied format, year, and timezone assumptions."""
    if current_user.role not in ("Admin", "Lead", "Analyst", "admin", "lead", "analyst"):
        abort(403)

    case = get_case_details(case_id)
    ev = get_evidence_details(evidence_id)
    if not case or not ev or ev["case_id"] != case_id:
        abort(404)

    log_format = request.form.get("log_format", "auth.log")
    try:
        year_assumption = int(request.form.get("year_assumption", "2026"))
        year_assumption = max(1990, min(2050, year_assumption))
    except ValueError:
        year_assumption = 2026

    try:
        tz_offset_hours = int(request.form.get("tz_offset_hours", "0"))
        tz_offset_hours = max(-12, min(14, tz_offset_hours))
    except ValueError:
        tz_offset_hours = 0

    try:
        res = analyze_log_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            log_format=log_format,
            year_assumption=year_assumption,
            tz_offset_hours=tz_offset_hours,
            acting_user_id=current_user.id,
        )

        critical_count = sum(1 for f in res["findings"] if f["severity"] == "Critical")
        high_count = sum(1 for f in res["findings"] if f["severity"] == "High")

        flash(
            f"Log analysis complete: {res['total_lines_parsed']} lines processed, "
            f"{len(res['findings'])} findings generated ({critical_count} Critical, {high_count} High), "
            f"and {len(res['flagged_ips'])} IOC leads flagged.",
            "success",
        )
    except Exception as e:
        flash(f"Log analysis failed: {e}", "error")

    return redirect(url_for("logs.view_logs", case_id=case_id, evidence_id=evidence_id))


@logs_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/logs/lines", methods=["GET"])
@case_member_required
def get_log_lines(case_id: int, evidence_id: int):
    """AJAX endpoint to safely fetch verbatim raw lines by line numbers."""
    lines_str = request.args.get("lines", "")
    if not lines_str:
        return jsonify({"lines": []})

    try:
        line_nums = [int(p.strip()) for p in lines_str.split(",") if p.strip().isdigit()]
    except Exception:
        line_nums = []

    # Bound line count to 100 for responsiveness
    line_nums = line_nums[:100]

    lines_data = get_raw_log_lines_by_numbers(
        case_id=case_id,
        evidence_id=evidence_id,
        line_numbers=line_nums,
        acting_user_id=current_user.id,
    )
    return jsonify({"lines": lines_data})


@logs_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/logs/export.json", methods=["GET"])
@case_member_required
def export_json(case_id: int, evidence_id: int):
    """Export log findings and extracted IOCs as JSON."""
    ev = get_evidence_details(evidence_id)
    if not ev or ev["case_id"] != case_id:
        abort(404)

    stored = get_stored_log_summary(case_id, evidence_id)
    payload = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "evidence_name": ev["display_name"],
        "sha256": ev["sha256"],
        "findings": stored["findings"],
        "iocs": stored["iocs"],
        "events_count": len(stored["events"]),
    }

    return Response(
        json.dumps(payload, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=log_analysis_{evidence_id}.json"},
    )


@logs_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/logs/export.csv", methods=["GET"])
@case_member_required
def export_csv(case_id: int, evidence_id: int):
    """Export normalized log events as CSV."""
    ev = get_evidence_details(evidence_id)
    if not ev or ev["case_id"] != case_id:
        abort(404)

    stored = get_stored_log_summary(case_id, evidence_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Line No", "Timestamp (UTC)", "Source IP", "Username", "Action", "Raw Log Line"])

    for item in stored["events"]:
        writer.writerow([
            item.get("line_no", ""),
            item.get("timestamp_utc", ""),
            item.get("src_ip", ""),
            item.get("username", ""),
            item.get("action", ""),
            item.get("raw_line", ""),
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=log_events_{evidence_id}.csv"},
    )
