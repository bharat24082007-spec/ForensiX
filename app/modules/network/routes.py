"""
ForensiX Network Packet Analysis Routes.
Provides routes to dissect PCAP/PCAPNG evidence files using TShark/Capinfos
or the native in-memory fallback parser, generating timeline events, IOCs,
and forensic findings.
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
from app.modules.network.service import (
    analyze_network_evidence,
    get_stored_network_summary,
)
from app.adapters.registry import is_tool_available, get_tool_info

network_bp = Blueprint("network", __name__, template_folder="../../templates")


@network_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/network", methods=["GET"])
@case_member_required
def view_network(case_id: int, evidence_id: int):
    """View packet dissection summary, top talkers, DNS queries, and findings."""
    case = get_case_details(case_id)
    ev = get_evidence_details(evidence_id)
    if not case or not ev or ev["case_id"] != case_id:
        abort(404)

    is_lead = (case["lead_user_id"] == current_user.id)
    can_analyze = current_user.role in ("Admin", "Lead", "Analyst", "admin", "lead", "analyst")

    tshark_available = is_tool_available("tshark")
    capinfos_available = is_tool_available("capinfos")
    tshark_info = get_tool_info("tshark") if tshark_available else None

    # Fetch existing stored events, IOCs, and findings
    stored = get_stored_network_summary(case_id, evidence_id)

    # If refresh requested or if not analyzed yet, run analysis
    analysis_data = None
    force_refresh = request.args.get("refresh") == "1"

    if force_refresh or (not stored["events"] and not stored["findings"] and not stored["iocs"]):
        try:
            analysis_data = analyze_network_evidence(
                case_id=case_id,
                evidence_id=evidence_id,
                packet_cap=200000,
                acting_user_id=current_user.id,
            )
            stored = get_stored_network_summary(case_id, evidence_id)
        except Exception as e:
            flash(f"Network packet analysis error: {e}", "warning")

    return render_template(
        "network/detail.html",
        active_nav="cases",
        active_tab="evidence",
        case=case,
        evidence=ev,
        is_lead=is_lead,
        can_analyze=can_analyze,
        tshark_available=tshark_available,
        capinfos_available=capinfos_available,
        tshark_info=tshark_info,
        analysis=analysis_data,
        events=stored["events"],
        iocs=stored["iocs"],
        findings=stored["findings"],
    )


@network_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/network/analyze", methods=["POST"])
@case_member_required
def trigger_analysis(case_id: int, evidence_id: int):
    """Trigger on-demand packet dissection and detection rules."""
    if current_user.role not in ("Admin", "Lead", "Analyst", "admin", "lead", "analyst"):
        abort(403)

    case = get_case_details(case_id)
    ev = get_evidence_details(evidence_id)
    if not case or not ev or ev["case_id"] != case_id:
        abort(404)

    try:
        packet_cap_raw = request.form.get("packet_cap", "200000")
        try:
            packet_cap = int(packet_cap_raw)
            packet_cap = max(100, min(1000000, packet_cap))
        except ValueError:
            packet_cap = 200000

        res = analyze_network_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            packet_cap=packet_cap,
            acting_user_id=current_user.id,
        )

        flash(
            f"Network analysis complete using {res['tool_used']}: {res['packet_count']} packets analyzed, "
            f"{res['events_count']} timeline flows, {res['iocs_count']} IOCs, and {len(res['findings'])} findings.",
            "success",
        )
    except Exception as e:
        flash(f"Network packet analysis failed: {e}", "error")

    return redirect(url_for("network.view_network", case_id=case_id, evidence_id=evidence_id))


@network_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/network/export.json", methods=["GET"])
@case_member_required
def export_json(case_id: int, evidence_id: int):
    """Export network analysis findings and IOCs as JSON."""
    ev = get_evidence_details(evidence_id)
    if not ev or ev["case_id"] != case_id:
        abort(404)

    stored = get_stored_network_summary(case_id, evidence_id)
    payload = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "evidence_name": ev["display_name"],
        "sha256": ev["sha256"],
        "findings": stored["findings"],
        "iocs": stored["iocs"],
        "events_count": len(stored["events"]),
    }

    resp = Response(
        json.dumps(payload, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=network_analysis_{evidence_id}.json"},
    )
    return resp


@network_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/network/export.csv", methods=["GET"])
@case_member_required
def export_csv(case_id: int, evidence_id: int):
    """Export network timeline events as CSV."""
    ev = get_evidence_details(evidence_id)
    if not ev or ev["case_id"] != case_id:
        abort(404)

    stored = get_stored_network_summary(case_id, evidence_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp (UTC)", "Source IP", "Destination IP", "Action", "Details"])

    for item in stored["events"]:
        writer.writerow([
            item.get("timestamp_utc", ""),
            item.get("src_ip", ""),
            item.get("dst_ip", ""),
            item.get("action", ""),
            item.get("raw_line", ""),
        ])

    resp = Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=network_events_{evidence_id}.csv"},
    )
    return resp
