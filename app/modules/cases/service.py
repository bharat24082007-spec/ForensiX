"""
ForensiX Case Management Service.
Handles case provisioning, auto-numbering (CASE-YYYY-XXXX),
member assignment, status transitions, legal hold protection, and metrics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.db import query_db, execute_db
from app.modules.custody.service import append as custody_append


def generate_next_case_no() -> str:
    """
    Generate sequential case identifier for the current year.
    Format: CASE-YYYY-XXXX (e.g. CASE-2026-0001).
    """
    current_year = datetime.now(timezone.utc).year
    prefix = f"CASE-{current_year}-"

    # Query latest case number for this year
    row = query_db(
        "SELECT case_no FROM cases WHERE case_no LIKE ? ORDER BY id DESC LIMIT 1",
        (f"{prefix}%",),
        one=True,
    )
    if not row:
        return f"{prefix}0001"

    last_no_str = row["case_no"]
    try:
        last_seq = int(last_no_str.split("-")[-1])
        next_seq = last_seq + 1
    except (ValueError, IndexError):
        next_seq = 1

    return f"{prefix}{next_seq:04d}"


def create_case(
    title: str,
    description: str,
    priority: str,
    lead_user_id: int,
) -> int:
    """
    Create a new forensic investigation case.
    Lead is automatically assigned as a case member.
    """
    clean_title = title.strip()
    if not clean_title:
        raise ValueError("Case title cannot be empty.")

    valid_priorities = {"Low", "Medium", "High", "Critical"}
    if priority not in valid_priorities:
        priority = "Medium"

    case_no = generate_next_case_no()

    case_id = execute_db(
        """
        INSERT INTO cases (case_no, title, description, status, priority, lead_user_id, legal_hold)
        VALUES (?, ?, ?, 'Open', ?, ?, 0)
        """,
        (case_no, clean_title, description.strip(), priority, lead_user_id),
    )

    # Automatically add the Lead as a member in case_members
    execute_db(
        "INSERT OR IGNORE INTO case_members (case_id, user_id) VALUES (?, ?)",
        (case_id, lead_user_id),
    )

    # Log initial custody entry for case creation
    custody_append(
        case_id=case_id,
        evidence_id=None,
        user_id=lead_user_id,
        action="CASE_CREATED",
        detail={"case_no": case_no, "title": clean_title},
    )

    return case_id


def list_cases_for_user(
    user_id: int,
    user_role: str,
    status_filter: Optional[str] = None,
    priority_filter: Optional[str] = None,
    my_cases_only: bool = False,
    search_query: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    List cases accessible to the user.
    Admin has NO access to cases unless explicitly assigned as a member (Separation of Duties).
    """
    sql = """
        SELECT DISTINCT c.id, c.case_no, c.title, c.description, c.status, c.priority,
               c.lead_user_id, c.legal_hold, c.created_at, c.closed_at,
               u.name AS lead_name,
               (SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.id AND e.withdrawn = 0) AS evidence_count
        FROM cases c
        JOIN users u ON c.lead_user_id = u.id
        LEFT JOIN case_members cm ON c.id = cm.case_id
        WHERE (c.lead_user_id = ? OR cm.user_id = ?)
    """
    params: List[Any] = [user_id, user_id]

    if status_filter and status_filter != "All":
        sql += " AND c.status = ?"
        params.append(status_filter)

    if priority_filter and priority_filter != "All":
        sql += " AND c.priority = ?"
        params.append(priority_filter)

    if my_cases_only:
        sql += " AND (c.lead_user_id = ?)"
        params.append(user_id)

    if search_query:
        sql += " AND (c.case_no LIKE ? OR c.title LIKE ?)"
        search_param = f"%{search_query.strip()}%"
        params.extend([search_param, search_param])

    sql += " ORDER BY c.id DESC"

    rows = query_db(sql, tuple(params))
    return [dict(r) for r in rows]


def get_case_details(case_id: int) -> Optional[Dict[str, Any]]:
    """Fetch complete case metadata including lead details."""
    row = query_db(
        """
        SELECT c.id, c.case_no, c.title, c.description, c.status, c.priority,
               c.lead_user_id, c.legal_hold, c.created_at, c.closed_at,
               u.name AS lead_name, u.username AS lead_username
        FROM cases c
        JOIN users u ON c.lead_user_id = u.id
        WHERE c.id = ?
        """,
        (case_id,),
        one=True,
    )
    return dict(row) if row else None


def get_case_members(case_id: int) -> List[Dict[str, Any]]:
    """List assigned members for a case."""
    rows = query_db(
        """
        SELECT u.id, u.name, u.username, u.role
        FROM case_members cm
        JOIN users u ON cm.user_id = u.id
        WHERE cm.case_id = ?
        ORDER BY u.name ASC
        """,
        (case_id,),
    )
    return [dict(r) for r in rows]


def assign_member(case_id: int, user_id: int, acting_user_id: int) -> None:
    """Assign a user to a case. Lead only."""
    # Verify acting user is the case lead
    case = get_case_details(case_id)
    if not case:
        raise ValueError("Case not found.")
    if case["lead_user_id"] != acting_user_id:
        raise PermissionError("Only the case lead can assign members.")

    # Target user must be active
    target_user = query_db("SELECT id, name, is_active FROM users WHERE id = ?", (user_id,), one=True)
    if not target_user or not target_user["is_active"]:
        raise ValueError("Target user does not exist or is inactive.")

    execute_db(
        "INSERT OR IGNORE INTO case_members (case_id, user_id) VALUES (?, ?)",
        (case_id, user_id),
    )

    # Custody log entry
    custody_append(
        case_id=case_id,
        evidence_id=None,
        user_id=acting_user_id,
        action="MEMBER_ASSIGNED",
        detail={"assigned_user_id": user_id},
    )


def remove_member(case_id: int, user_id: int, acting_user_id: int) -> None:
    """Remove a user from a case. Cannot remove the lead."""
    case = get_case_details(case_id)
    if not case:
        raise ValueError("Case not found.")
    if case["lead_user_id"] != acting_user_id:
        raise PermissionError("Only the case lead can remove members.")
    if case["lead_user_id"] == user_id:
        raise ValueError("Cannot remove the case lead from the investigation.")

    execute_db(
        "DELETE FROM case_members WHERE case_id = ? AND user_id = ?",
        (case_id, user_id),
    )

    # Custody log entry
    custody_append(
        case_id=case_id,
        evidence_id=None,
        user_id=acting_user_id,
        action="MEMBER_REMOVED",
        detail={"removed_user_id": user_id},
    )


def update_case_status(case_id: int, new_status: str, acting_user_id: int) -> None:
    """
    Update case status: Open -> In Progress -> Under Review -> Closed.
    Closing requires Lead role.
    Status change to Closed is strictly BLOCKED if Legal Hold is active!
    """
    valid_statuses = {"Open", "In Progress", "Under Review", "Closed"}
    if new_status not in valid_statuses:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {valid_statuses}")

    case = get_case_details(case_id)
    if not case:
        raise ValueError("Case not found.")

    if new_status == "Closed":
        if case["lead_user_id"] != acting_user_id:
            raise PermissionError("Only the case lead can close a case.")
        if case["legal_hold"]:
            raise PermissionError("Case cannot be closed while Legal Hold is active.")

    closed_at = datetime.now(timezone.utc).isoformat() if new_status == "Closed" else None

    execute_db(
        "UPDATE cases SET status = ?, closed_at = ? WHERE id = ?",
        (new_status, closed_at, case_id),
    )

    # Custody log entry
    custody_append(
        case_id=case_id,
        evidence_id=None,
        user_id=acting_user_id,
        action="STATUS_CHANGED",
        detail={"old_status": case["status"], "new_status": new_status},
    )


def toggle_legal_hold(case_id: int, acting_user_id: int) -> bool:
    """
    Toggle Legal Hold on/off. Lead only.
    When ON: Blocks evidence withdrawal, status closing, and report deletion.
    """
    case = get_case_details(case_id)
    if not case:
        raise ValueError("Case not found.")
    if case["lead_user_id"] != acting_user_id:
        raise PermissionError("Only the case lead can toggle Legal Hold.")

    new_state = 0 if case["legal_hold"] else 1
    execute_db("UPDATE cases SET legal_hold = ? WHERE id = ?", (new_state, case_id))

    action_label = "LEGAL_HOLD_ENABLED" if new_state else "LEGAL_HOLD_DISABLED"
    custody_append(
        case_id=case_id,
        evidence_id=None,
        user_id=acting_user_id,
        action=action_label,
        detail={"legal_hold": new_state},
    )

    return bool(new_state)


def get_case_overview_summary(case_id: int) -> Dict[str, Any]:
    """Retrieve overview metrics for a specific case."""
    ev_row = query_db(
        "SELECT COUNT(*) AS cnt, MAX(last_verified_at) AS last_check FROM evidence WHERE case_id = ? AND withdrawn = 0",
        (case_id,),
        one=True,
    )
    findings_row = query_db(
        "SELECT COUNT(*) AS cnt FROM findings WHERE case_id = ? AND status = 'Open'",
        (case_id,),
        one=True,
    )
    recent_activity = query_db(
        """
        SELECT c.id, c.action, c.timestamp_utc, c.entry_hash, u.name AS user_name
        FROM custody_log c
        LEFT JOIN users u ON c.user_id = u.id
        WHERE c.case_id = ?
        ORDER BY c.id DESC
        LIMIT 6
        """,
        (case_id,),
    )

    return {
        "evidence_count": ev_row["cnt"] if ev_row else 0,
        "last_integrity_check": ev_row["last_check"] if ev_row and ev_row["last_check"] else "Never",
        "open_findings": findings_row["cnt"] if findings_row else 0,
        "recent_activity": [dict(r) for r in recent_activity],
    }
