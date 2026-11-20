"""
ForensiX Metadata & EXIF Analysis Routes.
Provides routes to extract, view, and analyze hidden file metadata, GPS, EXIF tags,
and structural integrity anomalies.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
)
from flask_login import login_required, current_user

from app.security.rbac import case_member_required
from app.modules.cases.service import get_case_details
from app.modules.evidence.service import get_evidence_details
from app.modules.metadata.service import (
    analyze_evidence_metadata,
    get_stored_metadata_analysis,
)

metadata_bp = Blueprint("metadata", __name__, template_folder="../../templates")


@metadata_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/metadata", methods=["GET"])
@case_member_required
def view_metadata(case_id: int, evidence_id: int):
    """View metadata, EXIF properties, GPS coordinates, and timeline events for an evidence file."""
    case = get_case_details(case_id)
    ev = get_evidence_details(evidence_id)
    if not case or not ev or ev["case_id"] != case_id:
        abort(404)

    is_lead = (case["lead_user_id"] == current_user.id)
    force_refresh = request.args.get("refresh") == "1"

    # Fetch stored events & findings
    stored = get_stored_metadata_analysis(case_id, evidence_id)

    analysis_data = None
    if force_refresh or (not stored["events"] and not stored["findings"]):
        try:
            analysis_data = analyze_evidence_metadata(case_id, evidence_id, acting_user_id=current_user.id)
            stored = get_stored_metadata_analysis(case_id, evidence_id)
        except Exception as e:
            flash(f"Metadata extraction error: {e}", "error")

    return render_template(
        "metadata/detail.html",
        active_nav="cases",
        active_tab="evidence",
        case=case,
        evidence=ev,
        is_lead=is_lead,
        analysis=analysis_data,
        events=stored["events"],
        findings=stored["findings"],
    )


@metadata_bp.route("/cases/<int:case_id>/evidence/<int:evidence_id>/metadata/extract", methods=["POST"])
@case_member_required
def trigger_extract(case_id: int, evidence_id: int):
    """Trigger on-demand metadata re-extraction and timeline event sync."""
    try:
        res = analyze_evidence_metadata(case_id, evidence_id, acting_user_id=current_user.id)
        flash(f"Metadata re-extraction complete: {len(res['normalized_events'])} timeline events and {len(res['findings'])} findings updated.", "success")
    except Exception as e:
        flash(f"Metadata extraction failed: {e}", "error")

    return redirect(url_for("metadata.view_metadata", case_id=case_id, evidence_id=evidence_id))
