"""
ForensiX IOC Extractor Routes.
Provides listing, extraction trigger, and CSV export for Indicators of Compromise.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from app.db import query_db
from app.modules.iocs.service import (
    defang,
    export_iocs_csv,
    extract_and_store_iocs,
    get_case_iocs,
)
from app.security.rbac import case_member_required, role_required

iocs_bp = Blueprint("iocs", __name__, template_folder="../../templates")

_VALID_TYPES = ("ipv4", "domain", "url", "email", "hash_sha256", "hash_md5")
_VALID_VERDICTS = ("Unknown", "Known good", "Suspicious", "Known malicious", "No detections")


@iocs_bp.route("/cases/<int:case_id>/iocs", methods=["GET"])
@case_member_required
def ioc_list(case_id: int):
    """List all IOCs for a case with optional type/verdict filters."""
    from app.modules.cases.service import get_case_details

    case = get_case_details(case_id)
    if not case:
        abort(404)

    filter_type = request.args.get("type", "").strip() or None
    filter_verdict = request.args.get("verdict", "").strip() or None

    # Sanitize filter values to allowed enums
    if filter_type and filter_type not in _VALID_TYPES:
        filter_type = None
    if filter_verdict and filter_verdict not in _VALID_VERDICTS:
        filter_verdict = None

    iocs = get_case_iocs(case_id, filter_type=filter_type, filter_verdict=filter_verdict)

    # Defang all values before passing to template
    for ioc in iocs:
        ioc["defanged_value"] = defang(ioc["value"], ioc["type"])

    # Gather evidence list for extraction UI
    evidence_list = query_db(
        """SELECT id, display_name, source_type FROM evidence
           WHERE case_id = ? AND withdrawn = 0
           ORDER BY uploaded_at DESC""",
        (case_id,),
    )

    can_extract = current_user.role in ("Lead", "Analyst", "Admin")

    return render_template(
        "iocs/ioc_list.html",
        active_nav="cases",
        active_tab="iocs",
        case=case,
        iocs=iocs,
        evidence_list=evidence_list,
        filter_type=filter_type or "",
        filter_verdict=filter_verdict or "",
        valid_types=_VALID_TYPES,
        valid_verdicts=_VALID_VERDICTS,
        can_extract=can_extract,
    )


@iocs_bp.route(
    "/cases/<int:case_id>/iocs/extract/<int:evidence_id>",
    methods=["POST"],
)
@role_required("Lead", "Analyst", "Admin")
@case_member_required
def extract_from_evidence(case_id: int, evidence_id: int):
    """
    Trigger IOC extraction from the text content of an evidence item.
    The evidence raw_line / text content is read from the events table
    (populated by log/pcap/metadata parsers). Falls back to empty text
    gracefully with a warning if no text content is available.
    """
    from app.modules.evidence.service import get_evidence_details

    ev = get_evidence_details(evidence_id)
    if not ev or ev["case_id"] != case_id:
        abort(404)

    # Gather all raw_line entries stored for this evidence
    rows = query_db(
        "SELECT raw_line FROM events WHERE evidence_id = ? AND raw_line IS NOT NULL",
        (evidence_id,),
    )
    text_content = "\n".join(r["raw_line"] for r in rows if r["raw_line"])

    if not text_content:
        flash(
            "No parseable text content found for this evidence item. "
            "Run a log or network analysis first to populate event data.",
            "warning",
        )
        return redirect(url_for("iocs.ioc_list", case_id=case_id))

    summary = extract_and_store_iocs(
        case_id=case_id,
        evidence_id=evidence_id,
        text_content=text_content,
        source="extractor",
    )

    flash(
        f"IOC extraction complete: {summary['total']} IOC(s) found, "
        f"{summary['new']} new. "
        + ", ".join(f"{v} {k}" for k, v in summary["by_type"].items()),
        "success",
    )
    return redirect(url_for("iocs.ioc_list", case_id=case_id))


@iocs_bp.route("/cases/<int:case_id>/iocs/export.csv", methods=["GET"])
@case_member_required
def export_csv(case_id: int):
    """Download all case IOCs as a CSV file (values defanged)."""
    csv_content = export_iocs_csv(case_id)
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=iocs_case_{case_id}.csv"
        },
    )
