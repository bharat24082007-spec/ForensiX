"""
ForensiX Dashboard Routes.
HTTP handling for forensic status overview and metric displays.
"""

from __future__ import annotations

from pathlib import Path
from flask import Blueprint, render_template, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user
from app.modules.dashboard.service import get_dashboard_metrics, FEATURE_MAP, create_or_load_demo_case

dashboard_bp = Blueprint("dashboard", __name__, template_folder="../../templates")


@dashboard_bp.route("/", methods=["GET"])
def root():
    """Root landing route: returns platform running status and redirects to login or dashboard."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    return render_template("landing.html")


@dashboard_bp.route("/home", methods=["GET"])
@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def index():
    """Render the main forensic investigation dashboard."""
    metrics = get_dashboard_metrics()
    return render_template(
        "dashboard/index.html",
        active_nav="dashboard",
        metrics=metrics,
        features=FEATURE_MAP,
    )


@dashboard_bp.route("/dashboard/load-demo-case", methods=["POST"])
@login_required
def load_demo_case():
    """Load sample case with all demo artifacts and automated analysis (Admin or Lead only)."""
    if current_user.role not in ("Admin", "Lead"):
        abort(403)

    data_dir = Path(current_app.config["DATA_DIR"])
    vault_dir = Path(current_app.config["VAULT_DIR"])
    work_dir = Path(current_app.config["WORK_DIR"])
    reports_dir = Path(current_app.config["REPORTS_DIR"])

    try:
        case_id = create_or_load_demo_case(
            user_id=current_user.id,
            data_dir=data_dir,
            vault_dir=vault_dir,
            work_dir=work_dir,
            reports_dir=reports_dir,
        )
        flash("Demo case 'Operation Red Sandstorm' loaded with 6 forensic artifacts and automated analysis.", "success")
        return redirect(url_for("cases.case_overview", case_id=case_id))
    except Exception as e:
        flash(f"Failed to load demo case: {e}", "error")
        return redirect(url_for("dashboard.index"))
