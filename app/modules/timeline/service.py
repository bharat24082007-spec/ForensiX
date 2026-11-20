"""
ForensiX Investigation Timeline Service.
Merges events from the events table, evidence records, and custody_log into a unified
chronological timeline with ISO-8601 UTC timestamps, optional filters, and CSV export.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import re
from typing import Any, Dict, List, Optional

from app.db import query_db


def _normalize_iso(ts: Any) -> str:
    """Normalize any timestamp string or datetime object to UTC ISO-8601 string."""
    if not ts:
        return ""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.isoformat()
    s = str(ts).strip()
    if not s:
        return ""
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    if not (s.endswith("Z") or "+" in s or ("-" in s[10:])):
        s = s + "Z"
    return s


def _auto_run_parsers_if_needed(case_id: int) -> None:
    """Run analysis parsers automatically on any unanalyzed evidence items for this case."""
    try:
        evidence_items = query_db(
            "SELECT id, display_name, mime_real FROM evidence WHERE case_id = ? AND withdrawn = 0",
            (case_id,),
        )
        if not evidence_items:
            return

        for ev in evidence_items:
            ev_id = ev["id"]
            name = (ev["display_name"] or "").lower()
            mime = (ev["mime_real"] or "").lower()

            count_ev = query_db(
                "SELECT count(*) as c FROM events WHERE case_id = ? AND evidence_id = ?",
                (case_id, ev_id),
                one=True,
            )
            if count_ev and count_ev["c"] > 0:
                continue

            if name.endswith(".log") or "text" in mime:
                try:
                    from app.modules.logs.service import analyze_log_evidence
                    fmt = "auth.log" if "auth" in name else "web.log" if "web" in name or "access" in name else "auth.log"
                    analyze_log_evidence(case_id=case_id, evidence_id=ev_id, log_format=fmt)
                except Exception:
                    pass
            elif name.endswith(".pcap") or "pcap" in mime:
                try:
                    from app.modules.network.service import analyze_network_evidence
                    analyze_network_evidence(case_id=case_id, evidence_id=ev_id)
                except Exception:
                    pass
            elif any(name.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".tiff")) or "image" in mime:
                try:
                    from app.modules.metadata.service import analyze_evidence_metadata
                    analyze_evidence_metadata(case_id=case_id, evidence_id=ev_id)
                except Exception:
                    pass
    except Exception:
        pass


def get_merged_timeline_events(
    case_id: int,
    source_filter: Optional[str] = None,
    evidence_id_filter: Optional[int] = None,
    severity_filter: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 1000,
) -> List[Dict]:
    """
    Merge events from:
    - events table (from logs, pcap, metadata)
    - evidence intake timestamps
    - custody_log (action events for the case)

    Returns list sorted chronologically by timestamp_utc ASC, up to `limit` rows.
    """
    # 0. Auto-run analysis if events have not been generated yet
    _auto_run_parsers_if_needed(case_id)

    # 1. Build severity lookup: evidence_id -> {line_no: severity}
    findings_rows = query_db(
        """SELECT evidence_id, severity, evidence_lines
           FROM findings
           WHERE case_id = ? AND evidence_id IS NOT NULL""",
        (case_id,),
    )
    _SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    severity_map: Dict[int, Dict[int, str]] = {}
    for row in findings_rows:
        ev_id = row["evidence_id"]
        sev = row["severity"]
        lines_str = row["evidence_lines"] or ""
        for token in re.findall(r"\b\d+\b", lines_str):
            ln = int(token)
            current = severity_map.setdefault(ev_id, {}).get(ln, "Info")
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(current, 0):
                severity_map[ev_id][ln] = sev

    merged: List[Dict] = []

    # 2. Query events table
    events_sql = """
        SELECT ev.id, ev.timestamp_utc, ev.source_type AS source, ev.action,
               ev.src_ip, ev.evidence_id, ev.line_no, ev.raw_line,
               e.display_name AS evidence_name
        FROM events ev
        LEFT JOIN evidence e ON e.id = ev.evidence_id
        WHERE ev.case_id = ?
    """
    events_args: list = [case_id]

    if source_filter:
        if source_filter in ("auth.log", "generic.log"):
            events_sql += " AND (ev.source_type IN ('auth.log', 'generic.log') OR e.display_name LIKE '%auth.log%')"
        elif source_filter == "web.log":
            events_sql += " AND (ev.source_type = 'web.log' OR e.display_name LIKE '%web.log%')"
        elif source_filter == "pcap":
            events_sql += " AND (ev.source_type = 'pcap' OR e.display_name LIKE '%.pcap%')"
        elif source_filter == "metadata":
            events_sql += " AND ev.source_type = 'metadata'"
        elif source_filter in ("custody", "evidence"):
            events_sql += " AND 1=0"
        else:
            events_sql += " AND ev.source_type = ?"
            events_args.append(source_filter)

    if evidence_id_filter is not None:
        events_sql += " AND ev.evidence_id = ?"
        events_args.append(evidence_id_filter)
    if start_date:
        events_sql += " AND ev.timestamp_utc >= ?"
        events_args.append(start_date)
    if end_date:
        events_sql += " AND ev.timestamp_utc <= ?"
        events_args.append(end_date)

    events_rows = query_db(events_sql, tuple(events_args))

    for row in events_rows:
        ev_id = row["evidence_id"]
        line_no = row["line_no"]
        severity = "Info"
        if ev_id and line_no:
            severity = severity_map.get(ev_id, {}).get(line_no, "Info")

        merged.append({
            "id": f"ev_{row['id']}",
            "timestamp_utc": _normalize_iso(row["timestamp_utc"]),
            "source": row["source"],
            "action": row["action"],
            "src_ip": row["src_ip"] or "",
            "evidence_id": ev_id,
            "evidence_name": row["evidence_name"] or "",
            "severity": severity,
            "raw_line": row["raw_line"] or "",
        })

    # 3. Evidence intake timestamps
    include_evidence = (source_filter is None) or (source_filter in ("evidence", "file"))
    if include_evidence:
        ev_items = query_db(
            "SELECT id, display_name, uploaded_at, size FROM evidence WHERE case_id = ? AND withdrawn = 0",
            (case_id,),
        )
        for ev in ev_items:
            if evidence_id_filter is not None and ev["id"] != evidence_id_filter:
                continue
            ts_norm = _normalize_iso(ev["uploaded_at"])
            if start_date and ts_norm < start_date:
                continue
            if end_date and ts_norm > end_date:
                continue
            merged.append({
                "id": f"evi_{ev['id']}",
                "timestamp_utc": ts_norm,
                "source": "evidence",
                "action": f"EVIDENCE_INTAKE: {ev['display_name']}",
                "src_ip": "",
                "evidence_id": ev["id"],
                "evidence_name": ev["display_name"] or "",
                "severity": "Info",
                "raw_line": f"Forensic evidence file intake: {ev['display_name']} ({ev['size']} bytes)",
            })

    # 4. Custody log entries
    include_custody = (source_filter is None) or (source_filter == "custody")
    if include_custody:
        custody_sql = """
            SELECT cl.id, cl.timestamp_utc, cl.action, cl.user_id,
                   cl.evidence_id, cl.detail_json,
                   e.display_name AS evidence_name,
                   u.username
            FROM custody_log cl
            LEFT JOIN evidence e ON e.id = cl.evidence_id
            LEFT JOIN users u ON u.id = cl.user_id
            WHERE cl.case_id = ?
        """
        custody_args: list = [case_id]

        if evidence_id_filter is not None:
            custody_sql += " AND cl.evidence_id = ?"
            custody_args.append(evidence_id_filter)
        if start_date:
            custody_sql += " AND cl.timestamp_utc >= ?"
            custody_args.append(start_date)
        if end_date:
            custody_sql += " AND cl.timestamp_utc <= ?"
            custody_args.append(end_date)

        custody_rows = query_db(custody_sql, tuple(custody_args))
        for row in custody_rows:
            user_label = row["username"] or f"user_{row['user_id']}"
            merged.append({
                "id": f"cl_{row['id']}",
                "timestamp_utc": _normalize_iso(row["timestamp_utc"]),
                "source": "custody",
                "action": f"{row['action']} by {user_label}",
                "src_ip": "",
                "evidence_id": row["evidence_id"],
                "evidence_name": row["evidence_name"] or "",
                "severity": "Info",
                "raw_line": row["detail_json"] or "",
            })

    # 5. Apply severity filter
    if severity_filter and severity_filter != "Info":
        merged = [e for e in merged if e["severity"] == severity_filter]
    elif severity_filter == "Info":
        merged = [e for e in merged if e["severity"] == "Info"]

    # 6. Chronological sort (ascending UTC timestamps)
    merged.sort(key=lambda e: (e["timestamp_utc"] or ""))
    return merged[:limit]


def export_timeline_csv(case_id: int, **filters) -> str:
    """
    Export the merged timeline as a CSV string.
    The caller is responsible for logging the export in the custody chain.
    """
    events = get_merged_timeline_events(case_id, **filters)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Timestamp (UTC)", "Source", "Action",
        "Src IP", "Evidence ID", "Evidence Name", "Severity", "Raw Line",
    ])
    for ev in events:
        writer.writerow([
            ev["id"],
            ev["timestamp_utc"],
            ev["source"],
            ev["action"],
            ev["src_ip"],
            ev["evidence_id"] or "",
            ev["evidence_name"],
            ev["severity"],
            ev["raw_line"],
        ])
    return output.getvalue()
