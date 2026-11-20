"""
ForensiX Dashboard Service.
Computes case statistics, evidence integrity counts, and recent custody activity.
Strictly empty-state safe and parameterised.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict, List, Optional
from werkzeug.datastructures import FileStorage

from app.db import query_db
from tools.make_demo_data import generate_all_demo_data

FEATURE_MAP = [
    {
        "id": "s3",
        "name": "Case Management & Auto-Numbering",
        "purpose": "Sequential case provisioning (CASE-YYYY-XXXX), RBAC, investigator assignment, and Legal Hold.",
        "icon": "icon-cases",
        "status": "Built",
        "url": "/cases",
    },
    {
        "id": "s4",
        "name": "Secure Evidence Intake Vault",
        "purpose": "AES-256-GCM encrypted vault, SHA-256 fingerprinting, MIME spoofing & duplicate detection.",
        "icon": "icon-evidence",
        "status": "Built",
        "url": "/cases",
    },
    {
        "id": "s5",
        "name": "Cryptographic Chain of Custody",
        "purpose": "Append-only hash chain linking previous entry hashes and HMAC-SHA256 signatures.",
        "icon": "icon-shield",
        "status": "Built",
        "url": "/system/health",
    },
    {
        "id": "s7",
        "name": "Native Image Metadata Extraction",
        "purpose": "Forensic EXIF metadata parsing, camera make/model, and GPS coordinate extraction.",
        "icon": "icon-dashboard",
        "status": "Built",
        "url": "/cases",
    },
    {
        "id": "s8",
        "name": "PCAP Network Traffic Dissection",
        "purpose": "Offline TCP/UDP packet parsing, HTTP request reconstruction, and DNS query extraction.",
        "icon": "icon-refresh",
        "status": "Built",
        "url": "/cases",
    },
    {
        "id": "s9",
        "name": "Authentication & System Log Analysis",
        "purpose": "Automated detection of brute-force attacks and SUCCESS_AFTER_FAILURES indicators.",
        "icon": "icon-system",
        "status": "Built",
        "url": "/cases",
    },
    {
        "id": "s10",
        "name": "IOC Extraction & Defanging",
        "purpose": "Automated regex extraction of IPs, domains, URLs, hashes, and safe defanging.",
        "icon": "icon-alert-triangle",
        "status": "Built",
        "url": "/cases",
    },
    {
        "id": "s11",
        "name": "Interactive Forensic Timeline",
        "purpose": "Unified chronological event reconstruction across evidence artifacts.",
        "icon": "icon-refresh",
        "status": "Built",
        "url": "/cases",
    },
    {
        "id": "s12",
        "name": "Section 63 BSA Compliance Reporting",
        "purpose": "Court-ready PDF report generation with Section 63 BSA legal certificate.",
        "icon": "icon-reports",
        "status": "Built",
        "url": "/reports",
    },
    {
        "id": "s12_verify",
        "name": "Public Cryptographic Report Verification",
        "purpose": "Cryptographically verify PDF reports against SHA-256 hashes and Ed25519 signatures.",
        "icon": "icon-shield-check",
        "status": "Built",
        "url": "/verify-report",
    },
    {
        "id": "s13",
        "name": "Disaster Recovery & Master Key Export",
        "purpose": "Pre-flight database integrity checks, encrypted backups, and master key recovery.",
        "icon": "icon-save",
        "status": "Built",
        "url": "/system/backup",
    },
]


def create_or_load_demo_case(
    user_id: int,
    data_dir: Path,
    vault_dir: Path,
    work_dir: Path,
    reports_dir: Path,
) -> int:
    """Create a fully-populated demo case with all 6 artifacts and automated analyses."""
    from app.modules.cases.service import create_case
    from app.modules.evidence.service import intake_evidence
    from app.modules.metadata.service import analyze_evidence_metadata
    from app.modules.logs.service import analyze_log_evidence
    from app.modules.network.service import analyze_network_evidence
    from app.modules.iocs.service import extract_and_store_iocs
    from app.modules.reports.service import generate_forensic_report

    demo_dir = data_dir / "demo_artifacts"
    demo_files = generate_all_demo_data(demo_dir)

    title = "Operation Red Sandstorm (Demo Case)"
    desc = (
        "Multi-stage simulated incident: Unauthorized SSH brute-force breach (auth.log), "
        "suspicious field imagery with EXIF GPS (sample_photo.jpg), disguised executable payload "
        "(fake_photo.jpg), anti-malware test artifact (eicar.com), intercepted threat notes with IOCs "
        "(suspicious_notes.txt), and captured network traffic (sample.pcap)."
    )
    case_id = create_case(title, desc, "High", user_id)

    # 1. sample_photo.jpg -> metadata analysis
    if demo_files.get("sample_photo") and demo_files["sample_photo"].exists():
        photo_bytes = demo_files["sample_photo"].read_bytes()
        storage = FileStorage(stream=io.BytesIO(photo_bytes), filename="sample_photo.jpg")
        photo_id = intake_evidence(case_id, storage, user_id, vault_dir, work_dir, tags="image,field", notes="Field photograph from incident site")
        try:
            analyze_evidence_metadata(case_id, photo_id, user_id, vault_dir)
        except Exception:
            pass

    # 2. auth.log -> log analysis
    if demo_files.get("auth_log") and demo_files["auth_log"].exists():
        auth_bytes = demo_files["auth_log"].read_bytes()
        storage = FileStorage(stream=io.BytesIO(auth_bytes), filename="auth.log")
        auth_id = intake_evidence(case_id, storage, user_id, vault_dir, work_dir, tags="log,ssh", notes="Linux SSH authentication log showing breach")
        try:
            analyze_log_evidence(case_id, auth_id, user_id, vault_dir)
        except Exception:
            pass

    # 3. fake_photo.jpg -> disguised executable (triggers SUSPICIOUS flag)
    if demo_files.get("fake_photo") and demo_files["fake_photo"].exists():
        fake_bytes = demo_files["fake_photo"].read_bytes()
        storage = FileStorage(stream=io.BytesIO(fake_bytes), filename="fake_photo.jpg")
        intake_evidence(case_id, storage, user_id, vault_dir, work_dir, tags="executable,masqueraded", notes="Disguised executable with JPEG extension")

    # 4. eicar.com -> test virus
    if demo_files.get("eicar") and demo_files["eicar"].exists():
        eicar_bytes = demo_files["eicar"].read_bytes()
        storage = FileStorage(stream=io.BytesIO(eicar_bytes), filename="eicar.com")
        intake_evidence(case_id, storage, user_id, vault_dir, work_dir, tags="malware,eicar", notes="Standard EICAR anti-virus test file")

    # 5. suspicious_notes.txt -> IOC extraction
    if demo_files.get("notes") and demo_files["notes"].exists():
        notes_bytes = demo_files["notes"].read_bytes()
        storage = FileStorage(stream=io.BytesIO(notes_bytes), filename="suspicious_notes.txt")
        notes_id = intake_evidence(case_id, storage, user_id, vault_dir, work_dir, tags="notes,threat-intel", notes="Recovered text file containing C2 domains and hashes")
        try:
            extract_and_store_iocs(case_id, notes_id, user_id, demo_files["notes"].read_text(encoding="utf-8"))
        except Exception:
            pass

    # 6. sample.pcap -> network analysis
    if demo_files.get("pcap") and demo_files["pcap"].exists():
        pcap_bytes = demo_files["pcap"].read_bytes()
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="sample.pcap")
        pcap_id = intake_evidence(case_id, storage, user_id, vault_dir, work_dir, tags="pcap,network", notes="Packet capture containing DNS queries and HTTP connections")
        try:
            analyze_network_evidence(case_id, pcap_id, acting_user_id=user_id, vault_dir=vault_dir)
        except Exception:
            pass

    # 7. Generate draft Section 63 BSA report
    try:
        generate_forensic_report(case_id, user_id, reports_dir)
    except Exception:
        pass

    return case_id


def get_dashboard_metrics() -> Dict[str, Any]:
    """Retrieve operational statistics for the forensic dashboard."""
    # 1. Case counts
    open_cases_row = query_db(
        "SELECT COUNT(*) AS cnt FROM cases WHERE status != 'Closed'",
        one=True,
    )
    total_cases_row = query_db(
        "SELECT COUNT(*) AS cnt FROM cases",
        one=True,
    )
    open_cases = open_cases_row["cnt"] if open_cases_row else 0
    total_cases = total_cases_row["cnt"] if total_cases_row else 0

    # 2. Evidence counts and status breakdown
    evidence_count_row = query_db(
        "SELECT COUNT(*) AS cnt FROM evidence WHERE withdrawn = 0",
        one=True,
    )
    compromised_row = query_db(
        "SELECT COUNT(*) AS cnt FROM evidence WHERE integrity_status = 'COMPROMISED'",
        one=True,
    )
    suspicious_row = query_db(
        "SELECT COUNT(*) AS cnt FROM evidence WHERE integrity_status = 'SUSPICIOUS'",
        one=True,
    )
    total_evidence = evidence_count_row["cnt"] if evidence_count_row else 0
    compromised_count = compromised_row["cnt"] if compromised_row else 0
    suspicious_count = suspicious_row["cnt"] if suspicious_row else 0

    # 3. Overall Integrity Health
    if compromised_count > 0:
        overall_integrity = "COMPROMISED"
    elif suspicious_count > 0:
        overall_integrity = "SUSPICIOUS"
    else:
        overall_integrity = "VERIFIED"

    # 4. Recent Custody Log Activity (Last 5 records)
    recent_custody_rows = query_db(
        """
        SELECT c.id, c.case_id, c.action, c.timestamp_utc, c.entry_hash, u.name AS user_name,
               cases.case_no
        FROM custody_log c
        LEFT JOIN users u ON c.user_id = u.id
        LEFT JOIN cases ON c.case_id = cases.id
        ORDER BY c.id DESC
        LIMIT 5
        """
    )
    recent_custody: List[Dict[str, Any]] = [dict(row) for row in (recent_custody_rows or [])]

    # 5. Active Cases (Last 5 open/in progress cases)
    active_cases_rows = query_db(
        """
        SELECT c.id, c.case_no, c.title, c.status, c.priority, c.created_at, u.name AS lead_name
        FROM cases c
        LEFT JOIN users u ON c.lead_user_id = u.id
        WHERE c.status != 'Closed'
        ORDER BY c.id DESC
        LIMIT 5
        """
    )
    active_cases: List[Dict[str, Any]] = [dict(row) for row in (active_cases_rows or [])]

    return {
        "open_cases": open_cases,
        "total_cases": total_cases,
        "total_evidence": total_evidence,
        "compromised_count": compromised_count,
        "suspicious_count": suspicious_count,
        "overall_integrity": overall_integrity,
        "recent_custody": recent_custody,
        "active_cases": active_cases,
    }
