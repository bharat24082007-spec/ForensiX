"""
ForensiX Forensic Report Generator Service.
Generates signed PDF forensic reports with ReportLab, covering evidence inventory,
custody chain, timeline, findings, IOCs, and legal certification sections.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Table,
    TableStyle,
    Spacer,
    HRFlowable,
    PageBreak,
)

from app.db import query_db, execute_db
from app.modules.custody.service import append as custody_append, verify_chain
from app.security.crypto import (
    generate_ed25519_keypair,
    load_ed25519_private_key,
    get_master_key,
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 64), b""):
            h.update(chunk)
    return h.hexdigest()


def _ensure_user_keypair(user_id: int) -> None:
    """Generate and store Ed25519 keypair for user if not already present."""
    row = query_db(
        "SELECT sign_pub_key, sign_priv_key_enc FROM users WHERE id = ?",
        (user_id,),
        one=True,
    )
    if row and (not row["sign_pub_key"] or not row["sign_priv_key_enc"]):
        pub_hex, enc_priv_hex = generate_ed25519_keypair()
        execute_db(
            "UPDATE users SET sign_pub_key = ?, sign_priv_key_enc = ? WHERE id = ?",
            (pub_hex, enc_priv_hex, user_id),
        )


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles():
    styles = getSampleStyleSheet()
    custom = {
        "h1": ParagraphStyle("h1", parent=styles["Heading1"], fontSize=20, spaceAfter=12, textColor=colors.HexColor("#1a365d")),
        "h2": ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14, spaceAfter=8, textColor=colors.HexColor("#2c5282")),
        "h3": ParagraphStyle("h3", parent=styles["Heading3"], fontSize=12, spaceAfter=6, textColor=colors.HexColor("#2d3748")),
        "normal": styles["Normal"],
        "mono": ParagraphStyle("mono", parent=styles["Normal"], fontName="Courier", fontSize=8),
        "small": ParagraphStyle("small", parent=styles["Normal"], fontSize=8, textColor=colors.grey),
        "warn": ParagraphStyle("warn", parent=styles["Normal"], fontSize=11, textColor=colors.red, spaceAfter=8),
        "center": ParagraphStyle("center", parent=styles["Normal"], alignment=1, fontSize=12),
        "cover_title": ParagraphStyle("cover_title", parent=styles["Title"], fontSize=28, spaceAfter=16, textColor=colors.HexColor("#1a365d")),
        "cover_sub": ParagraphStyle("cover_sub", parent=styles["Normal"], fontSize=14, alignment=1, textColor=colors.HexColor("#4a5568")),
    }
    return custom


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_forensic_report(case_id: int, acting_user_id: int, reports_dir: Path) -> Path:
    """
    Generate a PDF forensic report with ReportLab covering all required sections.
    Returns the path to the generated PDF.
    """
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    styles = _build_styles()

    # ---- Fetch case data ----
    case = query_db(
        """
        SELECT c.id, c.case_no, c.title, c.description, c.status, c.priority,
               c.created_at, c.closed_at,
               u.name AS lead_name, u.username AS lead_username
        FROM cases c
        JOIN users u ON c.lead_user_id = u.id
        WHERE c.id = ?
        """,
        (case_id,),
        one=True,
    )
    if not case:
        raise ValueError(f"Case {case_id} not found")

    acting_user = query_db(
        "SELECT name, username, sign_pub_key FROM users WHERE id = ?",
        (acting_user_id,),
        one=True,
    )
    investigator_name = acting_user["name"] if acting_user else "Unknown"
    investigator_username = acting_user["username"] if acting_user else "unknown"
    pub_key_hex = acting_user["sign_pub_key"] if acting_user and acting_user["sign_pub_key"] else None
    pub_fingerprint = hashlib.sha256(bytes.fromhex(pub_key_hex)).hexdigest() if pub_key_hex else "Pending Signature Key Enrollment"

    gen_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ---- Chain verification ----
    chain_result = verify_chain(case_id)
    chain_ok = chain_result.get("status") == "OK"
    chain_head_hash = chain_result.get("head_hash", "N/A")

    # ---- Evidence ----
    evidence_rows = query_db(
        """
        SELECT e.id, e.display_name, e.sha256, e.integrity_status, e.size,
               e.uploaded_at, e.withdrawn, u.name AS uploader_name
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.id
        WHERE e.case_id = ?
        ORDER BY e.id ASC
        """,
        (case_id,),
    )
    evidence_list = [dict(r) for r in evidence_rows]
    compromised_evidence = [e for e in evidence_list if e["integrity_status"] == "COMPROMISED" and not e["withdrawn"]]

    # ---- Custody log ----
    custody_rows = query_db(
        """
        SELECT c.id, c.action, c.detail_json, c.timestamp_utc, c.entry_hash,
               u.name AS user_name, e.display_name AS evidence_name
        FROM custody_log c
        LEFT JOIN users u ON c.user_id = u.id
        LEFT JOIN evidence e ON c.evidence_id = e.id
        WHERE c.case_id = ?
        ORDER BY c.id ASC
        """,
        (case_id,),
    )
    custody_entries = [dict(r) for r in custody_rows]

    # ---- Timeline ----
    timeline_rows = query_db(
        """
        SELECT timestamp_utc, source_type, src_ip, dst_ip, username, action, raw_line
        FROM events
        WHERE case_id = ?
        ORDER BY timestamp_utc ASC
        LIMIT 100
        """,
        (case_id,),
    )
    timeline_events = [dict(r) for r in timeline_rows]

    # ---- Findings ----
    finding_rows = query_db(
        """
        SELECT rule, severity, src_ip, count, first_seen, last_seen, evidence_lines, status
        FROM findings
        WHERE case_id = ?
        ORDER BY severity DESC, first_seen ASC
        """,
        (case_id,),
    )
    findings = [dict(r) for r in finding_rows]

    # ---- IOCs ----
    ioc_rows = query_db(
        "SELECT type, value, verdict, source FROM iocs WHERE case_id = ? ORDER BY type, value",
        (case_id,),
    )
    iocs = [dict(r) for r in ioc_rows]

    # ---- Tool runs ----
    tool_rows = query_db(
        """
        SELECT tool, version, status, started_at, finished_at, input_sha256
        FROM tool_runs
        WHERE case_id = ?
        ORDER BY started_at ASC
        """,
        (case_id,),
    )
    tool_runs = [dict(r) for r in tool_rows]

    # ---- Build PDF ----
    file_name = f"report_{uuid.uuid4().hex}.pdf"
    output_path = reports_dir / file_name

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Forensic Report - {case['case_no']}",
        author="ForensiX Platform",
    )

    story = []

    # ================================================================
    # 1. COVER PAGE
    # ================================================================
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("FORENSIC INVESTIGATION REPORT", styles["cover_title"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2c5282")))
    story.append(Spacer(1, 0.5 * cm))

    cover_data = [
        ["Case Number:", case["case_no"]],
        ["Case Title:", case["title"]],
        ["Investigator:", f"{investigator_name} ({investigator_username})"],
        ["Lead Investigator:", case["lead_name"]],
        ["Report Generated:", gen_date],
        ["Platform:", "ForensiX Digital Forensics Platform"],
        ["Chain Status:", "✓ INTACT" if chain_ok else "⚠ BROKEN – CHAIN INTEGRITY COMPROMISED"],
    ]
    cover_table = Table(cover_data, colWidths=[5 * cm, 12 * cm])
    cover_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (1, 6), (1, 6), colors.red if not chain_ok else colors.HexColor("#276749")),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # ================================================================
    # WARNING BANNERS (if applicable)
    # ================================================================
    if not chain_ok:
        story.append(Paragraph(
            "⚠ WARNING: CHAIN OF CUSTODY INTEGRITY BROKEN",
            styles["warn"],
        ))
        story.append(Paragraph(
            f"The chain-of-custody for this case has been mathematically verified as BROKEN. "
            f"This report may not be admissible as-is. Reason: {chain_result.get('reason', 'Unknown')} "
            f"at entry ID {chain_result.get('broken_at_entry', 'N/A')}.",
            styles["normal"],
        ))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.red))
        story.append(Spacer(1, 0.4 * cm))

    if compromised_evidence:
        story.append(Paragraph(
            f"⚠ WARNING: {len(compromised_evidence)} EVIDENCE ITEM(S) SHOW COMPROMISED INTEGRITY",
            styles["warn"],
        ))
        for ev in compromised_evidence:
            story.append(Paragraph(
                f"  • {ev['display_name']} (SHA-256: {ev['sha256'][:16]}...) — status: COMPROMISED",
                styles["normal"],
            ))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.red))
        story.append(Spacer(1, 0.4 * cm))

    # ================================================================
    # 2. CASE SUMMARY
    # ================================================================
    story.append(Paragraph("1. Case Summary", styles["h2"]))
    summary_data = [
        ["Field", "Value"],
        ["Case Number", case["case_no"]],
        ["Title", case["title"]],
        ["Description", case["description"] or "—"],
        ["Status", case["status"]],
        ["Priority", case["priority"]],
        ["Created At", case["created_at"]],
        ["Closed At", case["closed_at"] or "Open"],
        ["Lead Investigator", case["lead_name"]],
    ]
    story.append(_build_table(summary_data, col_widths=[5 * cm, 12 * cm]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 3. EVIDENCE LIST
    # ================================================================
    story.append(Paragraph("2. Evidence Inventory", styles["h2"]))
    if evidence_list:
        ev_data = [["#", "Display Name", "SHA-256 (trunc)", "Integrity", "Size (B)", "Uploaded"]]
        for i, ev in enumerate(evidence_list, 1):
            ev_data.append([
                str(i),
                ev["display_name"],
                ev["sha256"][:16] + "...",
                ev["integrity_status"],
                str(ev["size"]),
                str(ev["uploaded_at"])[:16],
            ])
        ev_table = Table(ev_data, colWidths=[0.7 * cm, 4 * cm, 3.5 * cm, 2.5 * cm, 2 * cm, 3.5 * cm])
        ev_table.setStyle(_evidence_table_style(ev_data))
        story.append(ev_table)
    else:
        story.append(Paragraph("No evidence items recorded for this case.", styles["normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 4. CHAIN OF CUSTODY
    # ================================================================
    story.append(Paragraph("3. Chain of Custody Trail", styles["h2"]))
    story.append(Paragraph(
        f"Chain Verification Result: {'INTACT ✓' if chain_ok else 'BROKEN ⚠ — See warning above'}",
        styles["normal"],
    ))
    story.append(Paragraph(f"Chain Head Hash: {chain_head_hash}", styles["mono"]))
    story.append(Spacer(1, 0.3 * cm))

    if custody_entries:
        coc_data = [["#", "Action", "User", "Evidence", "Timestamp (UTC)", "Entry Hash"]]
        for i, entry in enumerate(custody_entries, 1):
            coc_data.append([
                str(i),
                entry["action"],
                entry.get("user_name") or "System",
                entry.get("evidence_name") or "—",
                str(entry["timestamp_utc"])[:16],
                entry["entry_hash"][:12] + "...",
            ])
        coc_table = Table(coc_data, colWidths=[0.7 * cm, 3.5 * cm, 2.5 * cm, 3 * cm, 3 * cm, 2.5 * cm])
        coc_table.setStyle(_basic_table_style())
        story.append(coc_table)
    else:
        story.append(Paragraph("No custody entries recorded.", styles["normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 5. TIMELINE
    # ================================================================
    story.append(Paragraph("4. Investigation Timeline (top 100 events)", styles["h2"]))
    if timeline_events:
        tl_data = [["Timestamp (UTC)", "Source", "Src IP", "Username", "Action"]]
        for ev in timeline_events:
            tl_data.append([
                str(ev["timestamp_utc"])[:16],
                ev["source_type"],
                ev.get("src_ip") or "—",
                ev.get("username") or "—",
                (ev.get("action") or "")[:60],
            ])
        tl_table = Table(tl_data, colWidths=[3.5 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm, 5.5 * cm])
        tl_table.setStyle(_basic_table_style())
        story.append(tl_table)
    else:
        story.append(Paragraph("No timeline events recorded for this case.", styles["normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 6. FINDINGS
    # ================================================================
    story.append(Paragraph("5. Findings", styles["h2"]))
    if findings:
        f_data = [["Rule", "Severity", "Src IP", "Count", "First Seen", "Status"]]
        for f in findings:
            f_data.append([
                f["rule"],
                f["severity"],
                f.get("src_ip") or "—",
                str(f["count"]),
                str(f.get("first_seen") or "—")[:16],
                f["status"],
            ])
        f_table = Table(f_data, colWidths=[4 * cm, 2.5 * cm, 2.5 * cm, 1.5 * cm, 3 * cm, 2.5 * cm])
        f_table.setStyle(_basic_table_style())
        story.append(f_table)
    else:
        story.append(Paragraph("No automated findings recorded.", styles["normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 7. IOCs
    # ================================================================
    story.append(Paragraph("6. Indicators of Compromise (IOCs)", styles["h2"]))
    if iocs:
        ioc_data = [["Type", "Value (defanged)", "Verdict", "Source"]]
        for ioc in iocs:
            ioc_data.append([
                ioc["type"],
                _defang_ioc(ioc["value"], ioc["type"])[:50],
                ioc["verdict"],
                ioc.get("source") or "—",
            ])
        ioc_table = Table(ioc_data, colWidths=[2.5 * cm, 6 * cm, 3.5 * cm, 4 * cm])
        ioc_table.setStyle(_basic_table_style())
        story.append(ioc_table)
    else:
        story.append(Paragraph("No IOCs recorded for this case.", styles["normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 8. TOOLS USED
    # ================================================================
    story.append(Paragraph("7. Forensic Tools Used", styles["h2"]))
    if tool_runs:
        t_data = [["Tool", "Version", "Status", "Started", "Finished"]]
        for tr in tool_runs:
            t_data.append([
                tr["tool"],
                tr["version"],
                tr["status"],
                str(tr["started_at"])[:16],
                str(tr.get("finished_at") or "—")[:16],
            ])
        t_table = Table(t_data, colWidths=[3.5 * cm, 2.5 * cm, 2 * cm, 4 * cm, 4 * cm])
        t_table.setStyle(_basic_table_style())
        story.append(t_table)
    else:
        story.append(Paragraph("No tool runs recorded for this case.", styles["normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 9. LIMITATIONS
    # ================================================================
    story.append(Paragraph("8. Limitations", styles["h2"]))
    limitations = [
        "This report is generated automatically by the ForensiX platform and represents the state of "
        "the investigation at the time of generation.",
        "File content analysis is limited to formats supported by the installed forensic tool adapters.",
        "Network packet analysis relies on tshark/Wireshark availability and may be incomplete for "
        "encrypted or malformed traffic.",
        "Timeline accuracy depends on system clock synchronization of source evidence.",
        "IOC reputation lookups are performed against local/offline cache only when EXTERNAL_LOOKUPS=false.",
        "This report should be reviewed and supplemented by qualified forensic investigators before "
        "submission to legal proceedings.",
    ]
    for lim in limitations:
        story.append(Paragraph(f"• {lim}", styles["normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 10. LEGAL BASIS
    # ================================================================
    story.append(Paragraph("9. Legal Basis", styles["h2"]))
    story.append(Paragraph(
        "This forensic investigation and report are conducted in accordance with the following legislation:",
        styles["normal"],
    ))
    story.append(Paragraph(
        "• Information Technology Act, 2000 (India) – Sections 65B, 66, 67, 79",
        styles["normal"],
    ))
    story.append(Paragraph(
        "• Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) – Electronic records admissibility and certification",
        styles["normal"],
    ))
    story.append(Paragraph(
        "• ISO/IEC 27037:2012 – Guidelines for identification, collection, acquisition, and preservation "
        "of digital evidence",
        styles["normal"],
    ))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 11. SECTION 63 CERTIFICATE (BSA 2023)
    # ================================================================
    story.append(PageBreak())
    story.append(Paragraph("10. Section 63 Certificate (Bharatiya Sakshya Adhiniyam, 2023)", styles["h2"]))
    story.append(Paragraph(
        "DISCLAIMER: Verify exact wording against the official BSA 2023 schedule before court use.",
        styles["warn"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    cert_text = f"""
I, {investigator_name} ({investigator_username}), duly authorised to act on behalf of the
investigating organisation, hereby certify that:

(a) The electronic records contained in this report were produced by the computer system
    identified as the ForensiX Digital Forensics Platform during ordinary course of investigation;

(b) Case Reference Number: {case["case_no"]} — "{case["title"]}";

(c) The electronic records are derived from information fed into the computer in ordinary course
    of investigation activities;

(d) The computer system was operating properly throughout the period of investigation;

(e) The SHA-256 hash of the generated PDF report is embedded in the reports table of the platform
    database, ensuring authenticity of this document;

(f) Chain-of-Custody Head Hash at time of report generation: {chain_head_hash};

(g) Signer Public Key Fingerprint (SHA-256): {pub_fingerprint};

(h) Report generated on: {gen_date}.

This certificate is issued under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023.
"""
    story.append(Paragraph(cert_text.strip(), styles["normal"]))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(f"Signed by: {investigator_name}", styles["normal"]))
    story.append(Paragraph(f"Date: {gen_date}", styles["normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ================================================================
    # 12. ISO/IEC 27037 HANDLING CHECKLIST
    # ================================================================
    story.append(Paragraph("11. ISO/IEC 27037 Handling Checklist", styles["h2"]))
    checklist = [
        ("Identification", "Digital evidence items were systematically identified and catalogued."),
        ("Collection", "Evidence collected in a forensically sound manner preserving integrity."),
        ("Acquisition", "Cryptographic hash (SHA-256) computed at intake and verified post-acquisition."),
        ("Preservation", "Evidence stored in AES-256-GCM encrypted vault, access logged to chain-of-custody."),
        ("Chain of Custody", "All access, transfers, and processing steps recorded in append-only hash-chained log."),
        ("Integrity Verification", "Periodic automated integrity re-verification via scheduled watchdog."),
        ("Documentation", "All forensic tool executions recorded with tool name, version, arguments, and hashes."),
        ("Competence", "Investigation conducted by trained forensic investigators with assigned platform roles."),
        ("Auditability", "Full audit trail available in custody log; this report generated from verified records."),
    ]
    cl_data = [["Requirement", "Compliance Note"]] + [[c[0], c[1]] for c in checklist]
    cl_table = Table(cl_data, colWidths=[4 * cm, 12 * cm])
    cl_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(cl_table)

    # Build PDF
    doc.build(story)
    return output_path


# ---------------------------------------------------------------------------
# Table style helpers
# ---------------------------------------------------------------------------

def _basic_table_style() -> TableStyle:
    return TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ])


def _build_table(data: List[List[str]], col_widths=None) -> Table:
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _evidence_table_style(data: List[List]) -> TableStyle:
    style = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, row in enumerate(data[1:], 1):
        # row[3] = integrity_status
        status = row[3] if len(row) > 3 else ""
        bg = colors.white if i % 2 == 0 else colors.HexColor("#f7fafc")
        if status == "COMPROMISED":
            bg = colors.HexColor("#fff5f5")
        style.append(("BACKGROUND", (0, i), (-1, i), bg))
    return TableStyle(style)


def _defang_ioc(value: str, ioc_type: str) -> str:
    """Defang IOC for safe display."""
    if ioc_type in ("ipv4",):
        return value.replace(".", "[.]")
    if ioc_type in ("domain",):
        return value.replace(".", "[.]")
    if ioc_type in ("url",):
        v = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
        return v.replace(".", "[.]")
    return value


# ---------------------------------------------------------------------------
# sign_report
# ---------------------------------------------------------------------------

def sign_report(
    report_id: int,
    user_id: int,
    password: str,
    keys_dir: Path,
    reports_dir: Optional[Path] = None,
) -> bool:
    """
    Step-up authentication: re-verify password, sign PDF SHA-256 with Ed25519 private key.
    Writes detached .sig file and records custody trail.
    Returns True on success, False on auth failure.
    """
    from app.security.auth import verify_password, hasher as _hasher
    from argon2.exceptions import VerifyMismatchError

    # Fetch user record with password hash
    user_row = query_db(
        "SELECT id, password_hash, sign_pub_key, sign_priv_key_enc FROM users WHERE id = ?",
        (user_id,),
        one=True,
    )
    if not user_row:
        return False

    # Step-up: re-verify password
    try:
        _hasher.verify(user_row["password_hash"], password)
    except Exception:
        return False

    # Ensure keypair exists
    _ensure_user_keypair(user_id)

    # Re-fetch (may have just been generated)
    user_row = query_db(
        "SELECT sign_pub_key, sign_priv_key_enc FROM users WHERE id = ?",
        (user_id,),
        one=True,
    )
    if not user_row or not user_row["sign_priv_key_enc"]:
        return False

    # Fetch report
    report_row = query_db(
        "SELECT id, case_id, file_name, sha256 FROM reports WHERE id = ?",
        (report_id,),
        one=True,
    )
    if not report_row:
        return False

    # Load private key and sign the stored SHA-256
    try:
        priv_key = load_ed25519_private_key(user_row["sign_priv_key_enc"])
        sha256_bytes = bytes.fromhex(report_row["sha256"])
        signature_bytes = priv_key.sign(sha256_bytes)
        signature_hex = signature_bytes.hex()
    except Exception:
        return False

    # Update signature in DB
    execute_db(
        "UPDATE reports SET signature = ?, signed_by = ? WHERE id = ?",
        (signature_hex, user_id, report_id),
    )

    # Detached signature file (C4)
    rep_dir = reports_dir or (Path(keys_dir).parent / "reports")
    if rep_dir.is_dir():
        sig_path = rep_dir / f"{report_row['file_name']}.sig"
        try:
            sig_path.write_text(signature_hex, encoding="utf-8")
        except Exception:
            pass

    # Custody entry
    custody_append(
        case_id=report_row["case_id"],
        evidence_id=None,
        user_id=user_id,
        action="REPORT_SIGNED",
        detail={"report_id": report_id, "file_name": report_row["file_name"]},
    )
    return True


# ---------------------------------------------------------------------------
# verify_report_signature
# ---------------------------------------------------------------------------

def verify_report_signature(
    pdf_bytes: Optional[bytes] = None,
    report_id: Optional[int] = None,
    report_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify Ed25519 signature and SHA-256 integrity on a PDF document or hash.
    Accepts:
    - pdf_bytes (from uploaded PDF file)
    - report_id (optional explicit ID)
    - report_hash (optional explicit SHA-256 hex string)
    Returns dict with authentic, signer, signed_at, reason, sha256.
    """
    computed_sha256 = hashlib.sha256(pdf_bytes).hexdigest() if pdf_bytes else None

    report_row = None
    if report_id:
        report_row = query_db(
            """
            SELECT r.id, r.sha256, r.signature, r.created_at,
                   u.name AS signer_name, u.username AS signer_username,
                   u.sign_pub_key
            FROM reports r
            JOIN users u ON r.signed_by = u.id
            WHERE r.id = ?
            """,
            (report_id,),
            one=True,
        )
    elif report_hash:
        clean_hash = report_hash.strip().lower()
        report_row = query_db(
            """
            SELECT r.id, r.sha256, r.signature, r.created_at,
                   u.name AS signer_name, u.username AS signer_username,
                   u.sign_pub_key
            FROM reports r
            JOIN users u ON r.signed_by = u.id
            WHERE LOWER(r.sha256) = ?
            ORDER BY r.id DESC
            LIMIT 1
            """,
            (clean_hash,),
            one=True,
        )
    elif computed_sha256:
        report_row = query_db(
            """
            SELECT r.id, r.sha256, r.signature, r.created_at,
                   u.name AS signer_name, u.username AS signer_username,
                   u.sign_pub_key
            FROM reports r
            JOIN users u ON r.signed_by = u.id
            WHERE LOWER(r.sha256) = ?
            ORDER BY r.id DESC
            LIMIT 1
            """,
            (computed_sha256.lower(),),
            one=True,
        )

    if not report_row:
        return {
            "authentic": False,
            "signer": None,
            "signed_at": None,
            "reason": "Report not found in database matching this file or hash",
            "sha256": computed_sha256 or report_hash,
        }

    # Verify SHA-256 matches if pdf_bytes were provided
    if computed_sha256 and computed_sha256.lower() != report_row["sha256"].lower():
        return {
            "authentic": False,
            "signer": report_row["signer_name"],
            "signed_at": report_row["created_at"],
            "reason": "PDF content hash does not match stored hash — document has been modified",
            "sha256": computed_sha256,
        }

    # Signature must be non-empty
    if not report_row["signature"] or report_row["signature"] == "":
        return {
            "authentic": False,
            "signer": report_row["signer_name"],
            "signed_at": report_row["created_at"],
            "reason": "Report has not been signed yet",
            "sha256": report_row["sha256"],
        }

    # Verify Ed25519 signature
    try:
        pub_bytes = bytes.fromhex(report_row["sign_pub_key"])
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = bytes.fromhex(report_row["signature"])
        sha256_bytes = bytes.fromhex(report_row["sha256"])
        pub_key.verify(sig_bytes, sha256_bytes)
    except Exception as e:
        return {
            "authentic": False,
            "signer": report_row["signer_name"],
            "signed_at": report_row["created_at"],
            "reason": f"Signature verification failed: {e}",
            "sha256": report_row["sha256"],
        }

    return {
        "authentic": True,
        "signer": f"{report_row['signer_name']} ({report_row['signer_username']})",
        "signed_at": report_row["created_at"],
        "reason": "Cryptographic signature and SHA-256 hash valid. Document is authentic and unmodified.",
        "sha256": report_row["sha256"],
        "report_id": report_row["id"],
    }


# ---------------------------------------------------------------------------
# list_case_reports
# ---------------------------------------------------------------------------

def list_case_reports(case_id: int) -> List[Dict[str, Any]]:
    """List all reports for a case with signer details."""
    rows = query_db(
        """
        SELECT r.id, r.case_id, r.file_name, r.sha256, r.signature,
               r.chain_head_hash, r.created_at,
               u.name AS signer_name, u.username AS signer_username
        FROM reports r
        JOIN users u ON r.signed_by = u.id
        WHERE r.case_id = ?
        ORDER BY r.id DESC
        """,
        (case_id,),
    )
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# get_report_path
# ---------------------------------------------------------------------------

def get_report_path(report_id: int, reports_dir: Path) -> Optional[Path]:
    """Get filesystem path to the report PDF."""
    row = query_db("SELECT file_name FROM reports WHERE id = ?", (report_id,), one=True)
    if not row:
        return None
    p = Path(reports_dir) / row["file_name"]
    return p if p.is_file() else None
