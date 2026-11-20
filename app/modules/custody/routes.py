"""
ForensiX Chain-of-Custody & Integrity Verification Routes.
Provides immutable chronological audit trails, verification triggers,
and system chain inspection.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    abort,
    current_app,
)
from flask_login import login_required, current_user

from app.security.rbac import role_required, case_member_required
from app.modules.cases.service import get_case_details, get_case_members
from app.modules.custody.service import (
    verify_chain,
    get_custody_entries,
)
from app.modules.integrity.service import verify_all_case_evidence
from app.modules.integrity.watchdog import get_watchdog_state, run_integrity_watchdog_job

custody_bp = Blueprint("custody", __name__, template_folder="../../templates")


@custody_bp.route("/cases/<int:case_id>/custody", methods=["GET"])
@case_member_required
def case_custody(case_id: int):
    """Case Custody Trail: displays immutable audit records and chain integrity status."""
    case = get_case_details(case_id)
    if not case:
        abort(404)

    is_lead = (case["lead_user_id"] == current_user.id)
    action_filter = request.args.get("action", "All")
    user_filter = request.args.get("user", type=int)
    evidence_filter = request.args.get("evidence", type=int)

    # Walk and verify chain integrity
    chain_result = verify_chain(case_id)

    # Fetch entries
    entries = get_custody_entries(
        case_id=case_id,
        action_filter=action_filter,
        user_filter=user_filter,
        evidence_filter=evidence_filter,
    )

    members = get_case_members(case_id)

    return render_template(
        "custody/index.html",
        active_nav="cases",
        active_tab="custody",
        case=case,
        is_lead=is_lead,
        chain_result=chain_result,
        entries=entries,
        members=members,
        action_filter=action_filter,
    )


@custody_bp.route("/cases/<int:case_id>/verify", methods=["POST"])
@case_member_required
def case_verify(case_id: int):
    """Trigger on-demand cryptographic verification of custody chain and evidence."""
    chain_result = verify_chain(case_id)

    verify_files = request.form.get("verify_files") == "1"
    evidence_result = None
    if verify_files:
        evidence_result = verify_all_case_evidence(case_id, acting_user_id=current_user.id)

    if chain_result["status"] == "OK":
        msg = f"Chain Intact: {chain_result['entries_count']} custody entries verified OK."
        if evidence_result:
            msg += f" Evidence check: {evidence_result['intact_count']}/{evidence_result['total']} files verified."
        flash(msg, "success")
    else:
        msg = f"INTEGRITY FAILURE: Custody chain broken at entry #{chain_result.get('broken_at_entry')}. Reason: {chain_result.get('reason')}"
        flash(msg, "error")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"chain": chain_result, "evidence": evidence_result})

    return redirect(url_for("custody.case_custody", case_id=case_id))


@custody_bp.route("/system/chain", methods=["GET"])
@role_required("Admin", "Lead")
def system_chain():
    """System-wide custody chain inspection (authentication, lockout, and system admin logs)."""
    action_filter = request.args.get("action", "All")
    chain_result = verify_chain(case_id=None)
    entries = get_custody_entries(case_id=None, action_filter=action_filter)
    watchdog_state = get_watchdog_state()

    return render_template(
        "custody/system_chain.html",
        active_nav="system",
        chain_result=chain_result,
        entries=entries,
        action_filter=action_filter,
        watchdog_state=watchdog_state,
    )


@custody_bp.route("/system/chain/verify", methods=["POST"])
@role_required("Admin", "Lead")
def system_chain_verify():
    """Verify system chain integrity."""
    chain_result = verify_chain(case_id=None)
    if chain_result["status"] == "OK":
        flash(f"System Chain Intact: {chain_result['entries_count']} audit entries verified OK.", "success")
    else:
        flash(f"SYSTEM CHAIN BROKEN at entry #{chain_result.get('broken_at_entry')}! {chain_result.get('reason')}", "error")

    return redirect(url_for("custody.system_chain"))


@custody_bp.route("/system/watchdog/run", methods=["POST"])
@role_required("Admin", "Lead")
def run_watchdog_now():
    """Trigger immediate background integrity watchdog sweep."""
    app_instance = current_app._get_current_object()
    res = run_integrity_watchdog_job(app_instance)
    if res.get("last_status") == "COMPROMISED_DETECTED":
        flash(f"Watchdog sweep finished with ALERTS: {res['last_compromised_count']} compromised items found!", "error")
    else:
        flash(f"Watchdog sweep finished successfully: {res['last_items_checked']} items verified intact.", "success")

    return redirect(request.referrer or url_for("custody.system_chain"))
