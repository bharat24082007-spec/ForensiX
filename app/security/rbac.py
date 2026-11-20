"""
ForensiX Role-Based Access Control (RBAC) & Separation of Duties.
Enforces role permissions and per-case membership.
Admin has NO access to case contents unless explicitly assigned as a case member.
Unassigned cases strictly return 404 (not 403) to prevent case ID enumeration.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable
from flask import abort, current_app, g, request
from flask_login import current_user, login_required

from app.db import query_db


def role_required(*allowed_roles: str) -> Callable:
    """Decorator ensuring current authenticated user holds one of the required roles."""
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        @login_required
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in allowed_roles:
                current_app.logger.warning(
                    f"Forbidden access: User '{current_user.username}' ({current_user.role}) "
                    f"attempted action requiring {allowed_roles}"
                )
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def case_member_required(fn: Callable) -> Callable:
    """
    Decorator ensuring current user is an explicitly assigned member or lead of the case.
    Admin is NOT granted case access by default (Separation of Duties).
    Returns 404 (Not Found) if case doesn't exist or user is not a member.
    """
    @wraps(fn)
    @login_required
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        case_id = kwargs.get("case_id") or kwargs.get("id")
        if case_id is None:
            abort(404)

        # Query case record
        case_row = query_db(
            "SELECT id, case_no, title, status, priority, lead_user_id, legal_hold FROM cases WHERE id = ?",
            (case_id,),
            one=True,
        )
        if not case_row:
            abort(404)

        # Check membership
        is_lead = (case_row["lead_user_id"] == current_user.id)
        is_member = False
        if not is_lead:
            member_check = query_db(
                "SELECT 1 FROM case_members WHERE case_id = ? AND user_id = ?",
                (case_id, current_user.id),
                one=True,
            )
            is_member = bool(member_check)

        # If user is neither lead nor an assigned member, return 404
        if not is_lead and not is_member:
            current_app.logger.warning(
                f"Case access blocked (404 returned): User '{current_user.username}' is not a member of Case ID {case_id}."
            )
            abort(404)

        # Store case on request context
        g.case = dict(case_row)
        return fn(*args, **kwargs)
    return wrapper


def user_has_case_access(user_id: int, user_role: str, case_id: int) -> bool:
    """
    Check if a user is explicitly assigned as lead or member of a case.
    Admin does NOT have implicit access without explicit assignment.
    """
    case_row = query_db(
        "SELECT lead_user_id FROM cases WHERE id = ?",
        (case_id,),
        one=True,
    )
    if not case_row:
        return False
    if case_row["lead_user_id"] == user_id:
        return True
    member_check = query_db(
        "SELECT 1 FROM case_members WHERE case_id = ? AND user_id = ?",
        (case_id, user_id),
        one=True,
    )
    return bool(member_check)
