"""
ForensiX Case Management Routes.
HTTP endpoints for case listing, creation, overview, member assignment,
status transitions, and Legal Hold control.
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
    current_app,
)
from flask_login import login_required, current_user

from app.db import query_db
from app.security.rbac import role_required, case_member_required
from app.modules.cases.service import (
    create_case,
    list_cases_for_user,
    get_case_details,
    get_case_members,
    assign_member,
    remove_member,
    update_case_status,
    toggle_legal_hold,
    get_case_overview_summary,
)

cases_bp = Blueprint("cases", __name__, template_folder="../../templates")


@cases_bp.route("/cases", methods=["GET"])
@login_required
def case_list():
    """List cases assigned to the current user with filtering and search."""
    status_filter = request.args.get("status", "All")
    priority_filter = request.args.get("priority", "All")
    my_cases = request.args.get("my_cases") == "1"
    search_query = request.args.get("q", "").strip()

    cases = list_cases_for_user(
        user_id=current_user.id,
        user_role=current_user.role,
        status_filter=status_filter,
        priority_filter=priority_filter,
        my_cases_only=my_cases,
        search_query=search_query or None,
    )

    return render_template(
        "cases/list.html",
        active_nav="cases",
        cases=cases,
        status_filter=status_filter,
        priority_filter=priority_filter,
        my_cases=my_cases,
        search_query=search_query,
    )


@cases_bp.route("/cases/new", methods=["GET", "POST"])
@cases_bp.route("/cases/create", methods=["GET", "POST"])
@role_required("Lead", "Admin")
def case_create():
    """Create a new forensic case. Lead or Admin role required."""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "Medium")

        try:
            case_id = create_case(
                title=title,
                description=description,
                priority=priority,
                lead_user_id=current_user.id,
            )
            current_app.logger.info(f"Lead '{current_user.username}' created case ID {case_id}.")
            flash("Case successfully created.", "success")
            return redirect(url_for("cases.case_overview", case_id=case_id))
        except ValueError as e:
            flash(str(e), "error")

    return render_template("cases/create.html", active_nav="cases")


@cases_bp.route("/cases/<int:case_id>", methods=["GET"])
@case_member_required
def case_overview(case_id: int):
    """Case Overview tab: displays case header, tabs, summary metrics, and member controls."""
    case = get_case_details(case_id)
    if not case:
        abort(404)

    members = get_case_members(case_id)
    summary = get_case_overview_summary(case_id)

    # Active users available to add as members (if current user is lead)
    is_lead = (case["lead_user_id"] == current_user.id)
    available_users = []
    if is_lead:
        assigned_ids = {m["id"] for m in members}
        rows = query_db(
            "SELECT id, name, username, role FROM users WHERE is_active = 1 ORDER BY name ASC"
        )
        available_users = [dict(r) for r in rows if r["id"] not in assigned_ids]

    return render_template(
        "cases/overview.html",
        active_nav="cases",
        active_tab="overview",
        case=case,
        members=members,
        summary=summary,
        is_lead=is_lead,
        available_users=available_users,
    )


@cases_bp.route("/cases/<int:case_id>/analysis", methods=["GET"])
@case_member_required
def case_analysis(case_id: int):
    """Case Analysis Hub: Overview of metadata, network traffic, and authentication log analyses."""
    case = get_case_details(case_id)
    if not case:
        abort(404)

    is_lead = (case["lead_user_id"] == current_user.id)
    evidence_rows = query_db(
        "SELECT id, display_name, size, mime_real, integrity_status, "
        "       sha256, uploaded_at "
        "FROM evidence WHERE case_id = ? AND withdrawn = 0 ORDER BY id ASC",
        (case_id,)
    )
    evidence_items = [dict(r) for r in (evidence_rows or [])]

    metadata_items = [e for e in evidence_items if any(ext in e['display_name'].lower() for ext in ['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.pdf', '.docx', '.xlsx'])]
    network_items = [e for e in evidence_items if any(ext in e['display_name'].lower() for ext in ['.pcap', '.pcapng', '.cap'])]
    log_items = [e for e in evidence_items if any(ext in e['display_name'].lower() for ext in ['.log', '.txt', 'auth', 'syslog', 'audit'])]

    return render_template(
        "cases/analysis.html",
        active_nav="cases",
        active_tab="analysis",
        case=case,
        is_lead=is_lead,
        evidence_items=evidence_items,
        metadata_items=metadata_items,
        network_items=network_items,
        log_items=log_items,
    )


@cases_bp.route("/cases/<int:case_id>/status", methods=["POST"])
@case_member_required
def case_change_status(case_id: int):
    """Update case status. Closing is blocked under Legal Hold and requires Lead role."""
    new_status = request.form.get("status", "").strip()
    try:
        update_case_status(case_id, new_status, current_user.id)
        current_app.logger.info(f"User '{current_user.username}' updated case ID {case_id} status to '{new_status}'.")
        flash(f"Case status updated to {new_status}.", "success")
    except (ValueError, PermissionError) as e:
        flash(str(e), "error")

    return redirect(url_for("cases.case_overview", case_id=case_id))


@cases_bp.route("/cases/<int:case_id>/legal-hold", methods=["POST"])
@case_member_required
def case_toggle_legal_hold(case_id: int):
    """Toggle Legal Hold flag. Lead role required."""
    try:
        new_state = toggle_legal_hold(case_id, current_user.id)
        status_str = "ENABLED" if new_state else "DISABLED"
        current_app.logger.info(f"Lead '{current_user.username}' {status_str} Legal Hold on case ID {case_id}.")
        flash(f"Legal Hold has been {status_str.lower()}.", "warning" if new_state else "success")
    except (ValueError, PermissionError) as e:
        flash(str(e), "error")

    return redirect(url_for("cases.case_overview", case_id=case_id))


@cases_bp.route("/cases/<int:case_id>/members/add", methods=["POST"])
@case_member_required
def case_add_member(case_id: int):
    """Assign a member to the case. Lead role required."""
    target_user_id = request.form.get("user_id", type=int)
    if not target_user_id:
        flash("Invalid user selection.", "error")
        return redirect(url_for("cases.case_overview", case_id=case_id))

    try:
        assign_member(case_id, target_user_id, current_user.id)
        current_app.logger.info(f"Lead '{current_user.username}' assigned user ID {target_user_id} to case ID {case_id}.")
        flash("Member assigned to case successfully.", "success")
    except (ValueError, PermissionError) as e:
        flash(str(e), "error")

    return redirect(url_for("cases.case_overview", case_id=case_id))


@cases_bp.route("/cases/<int:case_id>/members/remove", methods=["POST"])
@case_member_required
def case_remove_member(case_id: int):
    """Remove a member from the case. Lead role required."""
    target_user_id = request.form.get("user_id", type=int)
    if not target_user_id:
        flash("Invalid user selection.", "error")
        return redirect(url_for("cases.case_overview", case_id=case_id))

    try:
        remove_member(case_id, target_user_id, current_user.id)
        current_app.logger.info(f"Lead '{current_user.username}' removed user ID {target_user_id} from case ID {case_id}.")
        flash("Member removed from case.", "success")
    except (ValueError, PermissionError) as e:
        flash(str(e), "error")

    return redirect(url_for("cases.case_overview", case_id=case_id))
