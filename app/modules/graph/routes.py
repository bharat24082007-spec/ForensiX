"""
ForensiX Investigation Relationship Graph Routes.
Exposes interactive entity-relationship network visualizer and graph JSON endpoint.
"""

from __future__ import annotations

from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user

from app.security.rbac import case_member_required
from app.modules.cases.service import get_case_details
from app.modules.graph.service import build_case_graph

graph_bp = Blueprint("graph", __name__, template_folder="../../templates")


@graph_bp.route("/cases/<int:case_id>/graph", methods=["GET"])
@case_member_required
def graph_view(case_id: int):
    """Render interactive relationship graph view for a case."""
    case = get_case_details(case_id)
    if not case:
        abort(404)

    graph_data = build_case_graph(case_id)
    return render_template(
        "graph/graph_view.html",
        active_nav="cases",
        active_tab="graph",
        case=case,
        metrics=graph_data["metrics"],
    )


@graph_bp.route("/cases/<int:case_id>/graph/data", methods=["GET"])
@case_member_required
def graph_data_api(case_id: int):
    """JSON API returning nodes and edges for vis-network graph rendering."""
    types_param = request.args.get("types", "").strip()
    node_types = [t.strip() for t in types_param.split(",") if t.strip()] if types_param else None

    graph_data = build_case_graph(case_id, node_types=node_types)
    return jsonify(graph_data)
