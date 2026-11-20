"""
ForensiX Investigation Timeline Routes.
Provides the interactive vis-timeline page, a JSON data endpoint,
and a CSV export with custody-chain logging.
"""

from __future__ import annotations

import json

from flask import (
    Blueprint,
    Response,
    abort,
    jsonify,
    render_template,
    request,
)
from flask_login import current_user

from app.db import query_db
from app.modules.custody.service import append as custody_append
from app.modules.timeline.service import export_timeline_csv, get_merged_timeline_events
from app.security.rbac import case_member_required

timeline_bp = Blueprint("timeline", __name__, template_folder="../../templates")

_VALID_SOURCES = ("auth.log", "web.log", "generic.log", "pcap", "metadata", "custody", "evidence")
_VALID_SEVERITIES = ("Info", "Low", "Medium", "High", "Critical")


def _parse_filters() -> dict:
    """Extract and sanitize timeline filter params from request.args."""
    source = request.args.get("source", "").strip() or None
    if source and source not in _VALID_SOURCES:
        source = None

    try:
        evidence_id = int(request.args.get("evidence_id", ""))
    except (ValueError, TypeError):
        evidence_id = None

    severity = request.args.get("severity", "").strip() or None
    if severity and severity not in _VALID_SEVERITIES:
        severity = None

    start_date = request.args.get("start_date", "").strip() or None
    end_date = request.args.get("end_date", "").strip() or None

    return {
        "source_filter": source,
        "evidence_id_filter": evidence_id,
        "severity_filter": severity,
        "start_date": start_date,
        "end_date": end_date,
    }


@timeline_bp.route("/cases/<int:case_id>/timeline", methods=["GET"])
@case_member_required
def view(case_id: int):
    """Full investigation timeline page with vis-timeline widget and table view."""
    from app.modules.cases.service import get_case_details

    case = get_case_details(case_id)
    if not case:
        abort(404)

    filters = _parse_filters()

    # Gather evidence for filter dropdown
    evidence_list = query_db(
        """SELECT id, display_name FROM evidence
           WHERE case_id = ? AND withdrawn = 0
           ORDER BY uploaded_at DESC""",
        (case_id,),
    )

    return render_template(
        "timeline/timeline_view.html",
        active_nav="cases",
        active_tab="timeline",
        case=case,
        evidence_list=evidence_list,
        valid_sources=_VALID_SOURCES,
        valid_severities=_VALID_SEVERITIES,
        filters=filters,
        timeline_data_url=f"/cases/{case_id}/timeline/data",
    )


@timeline_bp.route("/cases/<int:case_id>/timeline/data", methods=["GET"])
@case_member_required
def data(case_id: int):
    """
    JSON endpoint for the vis-timeline widget.
    Returns list of event objects with start, content, and className.
    """
    filters = _parse_filters()
    events = get_merged_timeline_events(case_id=case_id, **filters)

    # Shape for vis-timeline DataSet: id, start, content, title, className
    vis_items = []
    for ev in events:
        severity = ev.get("severity", "Info")
        class_name = f"sev-{severity.lower()}"
        label = f"[{ev['source']}] {ev['action']}"
        if ev.get("src_ip"):
            label += f" ({ev['src_ip']})"
        vis_items.append({
            "id": ev["id"],
            "start": ev["timestamp_utc"],
            "content": label[:120],
            "title": (
                f"<b>{ev['action']}</b><br>"
                f"Source: {ev['source']}<br>"
                f"Severity: {severity}<br>"
                f"Evidence: {ev.get('evidence_name') or '—'}<br>"
                f"IP: {ev.get('src_ip') or '—'}"
            ),
            "className": class_name,
            # Also pass raw data for the table view
            "_raw": ev,
        })

    return jsonify(vis_items)


@timeline_bp.route("/cases/<int:case_id>/timeline/export.csv", methods=["GET"])
@case_member_required
def export_csv(case_id: int):
    """Download merged timeline as CSV. Logged in custody chain."""
    filters = _parse_filters()
    csv_content = export_timeline_csv(case_id=case_id, **filters)

    # Log export in custody chain
    custody_append(
        case_id,
        None,
        current_user.id,
        "EXPORT_TIMELINE_CSV",
        {"filters": {k: v for k, v in filters.items() if v is not None}},
    )

    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=timeline_case_{case_id}.csv"
        },
    )
