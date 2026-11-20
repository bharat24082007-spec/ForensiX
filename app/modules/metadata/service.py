"""
ForensiX Metadata & EXIF Analysis Service.
Coordinates deep metadata extraction via ExifTool (S6 engine) and Python-native fallbacks
(Pillow, pypdf, python-docx, pefile).
Detects file anomalies:
- JPEG trailing overlay data after EOF (FF D9)
- High Shannon entropy (obfuscation/packing)
- File extension vs MIME type discrepancies
Normalizes all timestamps to UTC and generates investigation timeline events.
"""

from __future__ import annotations

import io
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.db import query_db, execute_db
from app.modules.evidence.service import get_evidence_details, verify_and_decrypt_evidence
from app.adapters.exiftool import extract_exiftool_metadata

# Native fallback parsers
try:
    from PIL import Image as PILImage
    from PIL.ExifTags import TAGS as EXIF_TAGS, GPSTAGS
except ImportError:
    PILImage = None
    EXIF_TAGS = {}
    GPSTAGS = {}

try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None

try:
    import pefile
except ImportError:
    pefile = None


def compute_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    total = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def parse_timestamp_to_utc(ts_str: Any) -> Optional[Tuple[str, str]]:
    """
    Parse arbitrary metadata timestamp strings and normalize to ISO-8601 UTC.
    Returns: (timestamp_utc, timestamp_original) or None if unparseable.
    """
    if not ts_str or not isinstance(ts_str, (str, int, float)):
        return None

    orig_str = str(ts_str).strip()
    if not orig_str or orig_str.startswith("0000"):
        return None

    # Handle UNIX epoch timestamp integer/float
    if isinstance(ts_str, (int, float)) or (orig_str.isdigit() and len(orig_str) == 10):
        try:
            dt = datetime.fromtimestamp(float(orig_str), tz=timezone.utc)
            return dt.isoformat(), orig_str
        except Exception:
            pass

    # Pattern 1: EXIF standard "YYYY:MM:DD HH:MM:SS" or "YYYY:MM:DD HH:MM:SS+ZZ:ZZ"
    m = re.match(r"^(\d{4})[:\-](\d{2})[:\-](\d{2})[ T](\d{2}):(\d{2}):(\d{2})([+\-]\d{2}:?\d{2}|Z)?", orig_str)
    if m:
        try:
            y, mo, d, h, mi, s = map(int, m.groups()[:6])
            tz_part = m.group(7)
            if tz_part:
                tz_clean = tz_part.replace(":", "")
                if tz_clean == "Z":
                    dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
                else:
                    sign = 1 if tz_clean[0] == "+" else -1
                    hrs = int(tz_clean[1:3])
                    mins = int(tz_clean[3:5]) if len(tz_clean) >= 5 else 0
                    tz_offset = timezone(sign * datetime.timedelta(hours=hrs, minutes=mins))
                    dt = datetime(y, mo, d, h, mi, s, tzinfo=tz_offset).astimezone(timezone.utc)
            else:
                dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
            return dt.isoformat(), orig_str
        except Exception:
            pass

    # Pattern 2: PDF Date format "D:YYYYMMDDHHmmSSOHH'mm'"
    if orig_str.startswith("D:"):
        clean_pdf = orig_str[2:].replace("'", "")
        try:
            y = int(clean_pdf[0:4])
            mo = int(clean_pdf[4:6]) if len(clean_pdf) >= 6 else 1
            d = int(clean_pdf[6:8]) if len(clean_pdf) >= 8 else 1
            h = int(clean_pdf[8:10]) if len(clean_pdf) >= 10 else 0
            mi = int(clean_pdf[10:12]) if len(clean_pdf) >= 12 else 0
            s = int(clean_pdf[12:14]) if len(clean_pdf) >= 14 else 0
            dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
            return dt.isoformat(), orig_str
        except Exception:
            pass

    # Fallback ISO format parser
    try:
        dt = datetime.fromisoformat(orig_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat(), orig_str
    except Exception:
        return None


def _convert_dms_to_decimal(dms: Any, ref: Optional[str]) -> Optional[float]:
    """Convert degrees/minutes/seconds GPS tuple to decimal degrees."""
    try:
        if isinstance(dms, (int, float)):
            deg = float(dms)
        elif isinstance(dms, (list, tuple)) and len(dms) >= 3:
            deg = float(dms[0]) + float(dms[1]) / 60.0 + float(dms[2]) / 3600.0
        else:
            return None

        if ref and ref.upper() in ("S", "W"):
            deg = -deg
        return round(deg, 6)
    except Exception:
        return None


def extract_native_image_metadata(data: bytes) -> Dict[str, Any]:
    """Extract EXIF and camera metadata using Pillow."""
    if not PILImage:
        return {}

    try:
        img = PILImage.open(io.BytesIO(data))
        exif_raw = img._getexif() if hasattr(img, "_getexif") and img._getexif() else {}
        exif_named: Dict[str, Any] = {}
        gps_info: Dict[str, Any] = {}

        for tag_id, value in exif_raw.items():
            tag_name = EXIF_TAGS.get(tag_id, f"Tag_{tag_id}")
            if tag_name == "GPSInfo" and isinstance(value, dict):
                for g_id, g_val in value.items():
                    g_name = GPSTAGS.get(g_id, f"GPS_{g_id}")
                    gps_info[g_name] = g_val
            else:
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        value = str(value)
                exif_named[tag_name] = value

        # Parse GPS coordinates if available
        gps_lat = None
        gps_lon = None
        if gps_info:
            if "GPSLatitude" in gps_info:
                gps_lat = _convert_dms_to_decimal(gps_info["GPSLatitude"], gps_info.get("GPSLatitudeRef"))
            if "GPSLongitude" in gps_info:
                gps_lon = _convert_dms_to_decimal(gps_info["GPSLongitude"], gps_info.get("GPSLongitudeRef"))

        res: Dict[str, Any] = {
            "format": img.format,
            "width": img.width,
            "height": img.height,
            "mode": img.mode,
            "camera_make": exif_named.get("Make"),
            "camera_model": exif_named.get("Model"),
            "software": exif_named.get("Software"),
            "capture_time": exif_named.get("DateTimeOriginal") or exif_named.get("DateTime"),
            "gps_latitude": gps_lat,
            "gps_longitude": gps_lon,
            "all_exif": exif_named,
        }
        return res
    except Exception as e:
        return {"error": f"Pillow EXIF extraction error: {e}"}


def extract_native_pdf_metadata(data: bytes) -> Dict[str, Any]:
    """Extract PDF document properties using pypdf."""
    if not pypdf:
        return {}
    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
        meta = reader.metadata or {}
        res = {
            "page_count": len(reader.pages),
            "is_encrypted": reader.is_encrypted,
            "author": meta.get("/Author"),
            "creator": meta.get("/Creator"),
            "producer": meta.get("/Producer"),
            "title": meta.get("/Title"),
            "subject": meta.get("/Subject"),
            "created": meta.get("/CreationDate"),
            "modified": meta.get("/ModDate"),
        }
        return res
    except Exception as e:
        return {"error": f"pypdf extraction error: {e}"}


def extract_native_docx_metadata(data: bytes) -> Dict[str, Any]:
    """Extract Word document properties using python-docx."""
    if not docx:
        return {}
    try:
        doc = docx.Document(io.BytesIO(data))
        cp = doc.core_properties
        res = {
            "title": cp.title,
            "author": cp.author,
            "last_modified_by": cp.last_modified_by,
            "created": cp.created.isoformat() if cp.created else None,
            "modified": cp.modified.isoformat() if cp.modified else None,
            "revision": cp.revision,
            "category": cp.category,
            "comments": cp.comments,
        }
        return res
    except Exception as e:
        return {"error": f"python-docx extraction error: {e}"}


def extract_native_pe_metadata(data: bytes) -> Dict[str, Any]:
    """Extract executable headers, compilation time, and sections using pefile."""
    if not pefile:
        return {}
    try:
        pe = pefile.PE(data=data)
        compile_ts = pe.FILE_HEADER.TimeDateStamp
        compile_dt = datetime.fromtimestamp(compile_ts, tz=timezone.utc).isoformat() if compile_ts else None

        sections = []
        high_entropy_sections = []
        for s in pe.sections:
            sec_name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
            sec_entropy = round(s.get_entropy(), 3)
            sections.append({"name": sec_name, "entropy": sec_entropy, "size": s.SizeOfRawData})
            if sec_entropy > 7.2:
                high_entropy_sections.append(sec_name)

        # Detect packer hints
        packer_hints = []
        known_packers = ["UPX", "ASPack", "Themida", "VMProtect", "PECompact"]
        for s in sections:
            for kp in known_packers:
                if kp.lower() in s["name"].lower():
                    packer_hints.append(f"Section '{s['name']}' matches packer '{kp}'")

        imports_count = 0
        imported_dlls = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                imported_dlls.append(dll_name)
                imports_count += len(entry.imports)

        res = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "compile_time": compile_dt,
            "compile_timestamp": compile_ts,
            "subsystem": hex(pe.OPTIONAL_HEADER.Subsystem),
            "sections": sections,
            "high_entropy_sections": high_entropy_sections,
            "packer_hints": packer_hints,
            "imported_dlls": imported_dlls[:15],
            "total_imports": imports_count,
        }
        return res
    except Exception as e:
        return {"error": f"pefile extraction error: {e}"}


def check_jpeg_trailing_data(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Check if a JPEG image has extraneous payload bytes appended after the
    standard End-Of-Image marker (FF D9).
    """
    if len(data) < 4 or data[0:2] != b"\xff\xd8":
        return None  # Not a JPEG

    eoi_pos = data.rfind(b"\xff\xd9")
    if eoi_pos == -1:
        return None

    # Length after marker:
    marker_end = eoi_pos + 2
    trailing_bytes = len(data) - marker_end
    if trailing_bytes > 0:
        return {
            "eoi_offset": eoi_pos,
            "trailing_size": trailing_bytes,
            "trailing_entropy": compute_shannon_entropy(data[marker_end:]),
        }
    return None


def analyze_evidence_metadata(
    case_id: int,
    evidence_id: int,
    acting_user_id: Optional[int] = None,
    vault_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Execute full metadata analysis pipeline on evidence item.
    Populates investigation timeline events (events table) and flags findings.
    """
    ev = get_evidence_details(evidence_id)
    if not ev or ev["case_id"] != case_id:
        raise ValueError("Evidence item not found or does not belong to case.")

    from flask import current_app
    v_dir = vault_dir or Path(current_app.config["VAULT_DIR"])

    # 1. Decrypt evidence into memory buffer
    evidence_bytes, display_name, mime_real = verify_and_decrypt_evidence(
        evidence_id=evidence_id,
        vault_dir=v_dir,
        acting_user_id=acting_user_id,
        action="METADATA_ANALYSIS",
    )

    # 2. Run ExifTool (Primary Extractor)
    exiftool_res = extract_exiftool_metadata(case_id, evidence_id, acting_user_id)

    # 3. Native Extraction Fallback / Enrichment
    native_data: Dict[str, Any] = {}
    mime_lower = (mime_real or "").lower()

    if "image" in mime_lower or display_name.lower().endswith((".jpg", ".jpeg", ".png", ".tif", ".tiff")):
        native_data = extract_native_image_metadata(evidence_bytes)
    elif "pdf" in mime_lower or display_name.lower().endswith(".pdf"):
        native_data = extract_native_pdf_metadata(evidence_bytes)
    elif "word" in mime_lower or display_name.lower().endswith((".docx", ".doc")):
        native_data = extract_native_docx_metadata(evidence_bytes)
    elif "dosexec" in mime_lower or display_name.lower().endswith((".exe", ".dll", ".sys")):
        native_data = extract_native_pe_metadata(evidence_bytes)

    # 4. Hidden Data & Anomaly Analysis
    findings: List[Dict[str, Any]] = []

    # (a) Extension vs MIME mismatch check
    if ev.get("integrity_status") == "SUSPICIOUS":
        findings.append(
            {
                "title": "MIME Type / File Extension Discrepancy",
                "severity": "High",
                "category": "MIME Mismatch",
                "description": f"File extension '{Path(display_name).suffix}' does not match real MIME '{mime_real}'. Potential masquerading attack.",
                "details": {"display_name": display_name, "mime_real": mime_real},
            }
        )

    # (b) JPEG End-Of-Image Trailing Overlay Check
    jpeg_trail = check_jpeg_trailing_data(evidence_bytes)
    if jpeg_trail:
        findings.append(
            {
                "title": "Appended Trailing Data After JPEG End-Of-Image (FF D9)",
                "severity": "High",
                "category": "Steganography / Hidden Payload",
                "description": f"Found {jpeg_trail['trailing_size']} overlay bytes appended after JPEG EOF marker. Entropy of overlay: {jpeg_trail['trailing_entropy']:.2f}.",
                "details": jpeg_trail,
            }
        )

    # (c) High Shannon Entropy Check
    file_entropy = compute_shannon_entropy(evidence_bytes)
    if file_entropy > 7.5:
        findings.append(
            {
                "title": f"High Shannon Entropy Detected ({file_entropy:.2f}/8.0)",
                "severity": "Medium",
                "category": "Obfuscation / Packing",
                "description": "High entropy indicates that the file payload is compressed, encrypted, or packed.",
                "details": {"entropy": file_entropy, "size": len(evidence_bytes)},
            }
        )

    # (d) Executable Packer Hints
    if "packer_hints" in native_data and native_data["packer_hints"]:
        for hint in native_data["packer_hints"]:
            findings.append(
                {
                    "title": "Executable Packer Signature Detected",
                    "severity": "High",
                    "category": "Malware Obfuscation",
                    "description": hint,
                    "details": native_data.get("sections", []),
                }
            )

    # 5. Extract & Normalize Timestamps to UTC
    timestamp_candidates: List[Tuple[str, Any]] = []

    # From ExifTool
    if exiftool_res.get("success"):
        tags = exiftool_res["tags"]
        for k in ["DateTimeOriginal", "CreateDate", "ModifyDate", "FileModifyDate", "ProfileDateTime"]:
            if k in tags and tags[k]:
                timestamp_candidates.append((f"ExifTool {k}", tags[k]))

    # From Native Parsers
    if "capture_time" in native_data and native_data["capture_time"]:
        timestamp_candidates.append(("Image Capture Time", native_data["capture_time"]))
    if "created" in native_data and native_data["created"]:
        timestamp_candidates.append(("Document Created", native_data["created"]))
    if "modified" in native_data and native_data["modified"]:
        timestamp_candidates.append(("Document Modified", native_data["modified"]))
    if "compile_time" in native_data and native_data["compile_time"]:
        timestamp_candidates.append(("PE Compilation Time", native_data["compile_time"]))

    normalized_events: List[Dict[str, Any]] = []
    seen_timestamps = set()

    for label, raw_ts in timestamp_candidates:
        parsed = parse_timestamp_to_utc(raw_ts)
        if parsed:
            utc_iso, orig_str = parsed
            key = f"{label}:{utc_iso}"
            if key not in seen_timestamps:
                seen_timestamps.add(key)
                normalized_events.append(
                    {
                        "label": label,
                        "timestamp_utc": utc_iso,
                        "timestamp_original": orig_str,
                    }
                )

    # 6. Database Updates: Sync events and findings tables
    # Clean previous metadata events/findings for this evidence item to avoid duplication
    execute_db("DELETE FROM events WHERE evidence_id = ? AND source_type = 'metadata'", (evidence_id,))
    execute_db(
        "DELETE FROM findings WHERE evidence_id = ? AND rule IN ('MIME_MISMATCH', 'JPEG_OVERLAY_DATA', 'HIGH_SHANNON_ENTROPY', 'PACKER_DETECTED')",
        (evidence_id,),
    )

    # Insert timeline events
    for ev_item in normalized_events:
        execute_db(
            """
            INSERT INTO events (case_id, evidence_id, timestamp_utc, source_type, action, raw_line)
            VALUES (?, ?, ?, 'metadata', 'FILE_TIMESTAMP', ?)
            """,
            (case_id, evidence_id, ev_item["timestamp_utc"], f"Metadata timestamp ({ev_item['label']}): {ev_item['timestamp_original']}"),
        )

    # Insert findings
    now_utc = datetime.now(timezone.utc).isoformat()
    for f in findings:
        rule_name = (
            "MIME_MISMATCH" if f["category"] == "MIME Mismatch"
            else "JPEG_OVERLAY_DATA" if "JPEG" in f["category"] or "Steganography" in f["category"]
            else "HIGH_SHANNON_ENTROPY" if "Entropy" in f["title"]
            else "PACKER_DETECTED"
        )
        execute_db(
            """
            INSERT INTO findings (case_id, evidence_id, rule, severity, status, evidence_lines, first_seen, last_seen)
            VALUES (?, ?, ?, ?, 'Open', ?, ?, ?)
            """,
            (case_id, evidence_id, rule_name, f["severity"], f["description"], now_utc, now_utc),
        )

    # Extract GPS if present (from ExifTool or Pillow)
    gps_lat = None
    gps_lon = None
    gps_alt = None

    if exiftool_res.get("success"):
        tags = exiftool_res["tags"]
        gps_lat = tags.get("GPSLatitude")
        gps_lon = tags.get("GPSLongitude")
        gps_alt = tags.get("GPSAltitude")
    elif "gps_latitude" in native_data and native_data["gps_latitude"] is not None:
        gps_lat = native_data["gps_latitude"]
        gps_lon = native_data["gps_longitude"]

    gps_data = None
    if gps_lat is not None and gps_lon is not None:
        gps_data = {
            "latitude": float(gps_lat),
            "longitude": float(gps_lon),
            "altitude": float(gps_alt) if gps_alt is not None else None,
            "text": f"{abs(float(gps_lat)):.6f}° {'N' if float(gps_lat) >= 0 else 'S'}, {abs(float(gps_lon)):.6f}° {'E' if float(gps_lon) >= 0 else 'W'}",
        }

    return {
        "evidence_id": evidence_id,
        "display_name": display_name,
        "mime_real": mime_real,
        "entropy": file_entropy,
        "exiftool": exiftool_res,
        "native": native_data,
        "findings": findings,
        "normalized_events": normalized_events,
        "gps": gps_data,
    }


def get_stored_metadata_analysis(case_id: int, evidence_id: int) -> Dict[str, Any]:
    """Retrieve existing events and findings without re-running full decryption."""
    events = query_db(
        """
        SELECT id, timestamp_utc, source_type, action, raw_line
        FROM events
        WHERE evidence_id = ? AND source_type = 'metadata'
        ORDER BY timestamp_utc ASC
        """,
        (evidence_id,),
    )
    findings = query_db(
        """
        SELECT id, rule, severity, status, evidence_lines, first_seen, last_seen
        FROM findings
        WHERE evidence_id = ?
        ORDER BY id DESC
        """,
        (evidence_id,),
    )
    return {
        "events": [dict(e) for e in events],
        "findings": [dict(f) for f in findings],
    }
