"""
ForensiX Evidence Vault Service.
Implements secure intake pipeline, SHA-256 intake fingerprinting,
chunked AES-256-GCM encryption at rest, path traversal neutralization,
MIME vs extension discrepancy detection, integrity re-verification on access,
and Legal-Hold-compliant withdrawal.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from werkzeug.datastructures import FileStorage

from app.db import query_db, execute_db
from app.security.crypto import (
    encrypt_file_aes_gcm_chunked,
    decrypt_stream_aes_gcm_chunked,
)
from app.modules.custody.service import append as custody_append

# Detect MIME type using python-magic
try:
    import magic
    _HAS_MAGIC = True
except ImportError:
    magic = None
    _HAS_MAGIC = False


# Small built-in magic-number table (C6 fallback for libmagic)
_MAGIC_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"MZ", "application/x-dosexec"),
    (b"\x7fELF", "application/x-executable"),
    (b"%PDF", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"PK\x03\x04", "application/zip"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
]


def is_magic_available() -> bool:
    """Check whether python-magic is active or running in fallback mode."""
    return _HAS_MAGIC


def fallback_magic_mime(header_bytes: bytes) -> str:
    """Inspect header bytes against built-in table (MZ, ELF, PDF, PNG, JPEG, ZIP, GIF)."""
    for sig, mime in _MAGIC_SIGNATURES:
        if header_bytes.startswith(sig):
            return mime
    return "application/octet-stream"


class DuplicateEvidenceError(ValueError):
    """Raised when an evidence file with identical SHA-256 already exists in the case."""
    def __init__(self, message: str, existing_evidence_id: int, existing_filename: str, sha256: str):
        super().__init__(message)
        self.existing_evidence_id = existing_evidence_id
        self.existing_filename = existing_filename
        self.sha256 = sha256


def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename to prevent directory traversal attacks.
    Strips directory separators, null bytes, and path components, keeping only the basename.
    """
    if not filename:
        return "unnamed_evidence"

    # Replace backslashes with forward slashes, strip null bytes
    cleaned = filename.replace("\\", "/").replace("\x00", "")
    # Take basename only
    base = os.path.basename(cleaned).strip()
    # Remove any leading periods or path traversal remnants
    while base.startswith("../") or base.startswith("./") or base.startswith(".."):
        base = base.lstrip("./")

    return base or "unnamed_evidence"


def detect_mime_and_suspicious_mismatch(file_path: Path, filename: str) -> Tuple[str, bool]:
    """
    Inspect real magic bytes of a file and detect extension mismatches.
    Flags fake extensions (e.g. photo.jpg containing an MZ executable).
    Falls back to built-in signature table if libmagic is unavailable (C6).
    Returns: (detected_mime, is_suspicious).
    """
    with open(file_path, "rb") as f:
        header = f.read(16)

    detected_mime = "application/octet-stream"
    if _HAS_MAGIC:
        try:
            detected_mime = magic.from_file(str(file_path), mime=True)
        except Exception:
            pass

    # Apply built-in fallback table if generic octet-stream
    if detected_mime == "application/octet-stream":
        detected_mime = fallback_magic_mime(header)

    is_executable = (
        header.startswith(b"MZ") or
        header.startswith(b"\x7fELF") or
        header.startswith(b"\xca\xfe\xba\xbe") or
        header.startswith(b"\xfe\xed\xfa\xce") or
        "executable" in detected_mime or
        "dosexec" in detected_mime
    )

    ext = Path(filename).suffix.lower()
    benign_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".pdf", ".docx", ".xlsx", ".csv"}

    # If benign extension but header reveals executable code -> flag suspicious!
    is_suspicious = False
    if ext in benign_exts and is_executable:
        is_suspicious = True

    return detected_mime, is_suspicious


def intake_evidence(
    case_id: int,
    file_storage: FileStorage,
    uploaded_by_user_id: int,
    vault_dir: Path,
    work_dir: Path,
    tags: str = "",
    notes: str = "",
    source_type: str = "upload",
    confirm_duplicate: bool = False,
) -> int:
    """
    Forensic intake pipeline (single transactional function):
    1. Stream upload to data/work/ while computing SHA-256 of the plaintext.
    2. Check for duplicate SHA-256 in same case; require confirmation (C5).
    3. Inspect magic bytes vs extension for tampering (C6 fallback).
    4. Encrypt in chunks (AES-256-GCM) into data/vault/<uuid>.enc.
    5. Set vault file read-only at OS level.
    6. Insert evidence row with SHA-256 and integrity status.
    7. Write UPLOAD custody log entry (with duplicate confirmation audit if applicable).
    8. Wipe working file.
    """
    safe_display_name = sanitize_filename(file_storage.filename or "evidence")
    work_dir.mkdir(parents=True, exist_ok=True)
    vault_dir.mkdir(parents=True, exist_ok=True)

    temp_filename = f"intake_{uuid.uuid4().hex}.tmp"
    temp_path = work_dir / temp_filename

    sha256_hasher = hashlib.sha256()
    file_size = 0

    try:
        # Step 1: Stream to data/work/ while hashing plaintext
        with open(temp_path, "wb") as f_out:
            while True:
                chunk = file_storage.stream.read(1024 * 1024)
                if not chunk:
                    break
                sha256_hasher.update(chunk)
                file_size += len(chunk)
                f_out.write(chunk)

        plaintext_sha256 = sha256_hasher.hexdigest()

        # Step 2: Check duplicate SHA-256 in the same case (C5)
        existing = query_db(
            """
            SELECT id, display_name, sha256 FROM evidence
            WHERE case_id = ? AND sha256 = ? AND withdrawn = 0
            LIMIT 1
            """,
            (case_id, plaintext_sha256),
            one=True,
        )
        is_duplicate = False
        if existing:
            if not confirm_duplicate:
                raise DuplicateEvidenceError(
                    f"Duplicate evidence detected: file with SHA-256 {plaintext_sha256[:16]}... already exists as '{existing['display_name']}' (ID #{existing['id']}).",
                    existing_evidence_id=existing["id"],
                    existing_filename=existing["display_name"],
                    sha256=plaintext_sha256,
                )
            is_duplicate = True

        # Step 3: Detect real MIME and flag extension mismatch
        detected_mime, is_suspicious = detect_mime_and_suspicious_mismatch(temp_path, safe_display_name)
        initial_integrity = "SUSPICIOUS" if is_suspicious else "VERIFIED"

        # Step 4: Encrypt chunked into data/vault/<uuid>.enc
        vault_uuid = f"{uuid.uuid4().hex}.enc"
        vault_path = vault_dir / vault_uuid
        encrypt_file_aes_gcm_chunked(src_path=temp_path, dst_path=vault_path)

        # Step 5: Set vault file read-only
        try:
            os.chmod(vault_path, stat.S_IREAD)
        except (OSError, NotImplementedError):
            pass

        # Step 6: Insert evidence record
        now_utc = datetime.now(timezone.utc).isoformat()
        evidence_id = execute_db(
            """
            INSERT INTO evidence (case_id, display_name, stored_name, size, mime_real,
                                 sha256, integrity_status, source_type, tags, notes,
                                 withdrawn, uploaded_by, uploaded_at, last_verified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (case_id, safe_display_name, vault_uuid, file_size, detected_mime,
             plaintext_sha256, initial_integrity, source_type, tags.strip(), notes.strip(),
             uploaded_by_user_id, now_utc, now_utc),
        )

        # Step 7: Write UPLOAD custody log entry
        custody_detail = {
            "name": safe_display_name,
            "sha256": plaintext_sha256,
            "size": file_size,
            "mime": detected_mime,
            "integrity": initial_integrity,
        }
        if is_duplicate:
            custody_detail["duplicate_confirmed"] = True
            custody_detail["existing_evidence_id"] = existing["id"]

        custody_append(
            case_id=case_id,
            evidence_id=evidence_id,
            user_id=uploaded_by_user_id,
            action="UPLOAD",
            detail=custody_detail,
            timestamp_utc=now_utc,
        )

        return evidence_id

    finally:
        # Step 7: Wipe working file
        if temp_path.is_file():
            try:
                # Overwrite bytes before unlink
                with open(temp_path, "ba+", buffering=0) as f_wipe:
                    length = f_wipe.tell()
                    f_wipe.seek(0)
                    f_wipe.write(b"\x00" * min(length, 4096))
            except Exception:
                pass
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


def verify_and_decrypt_evidence(
    evidence_id: int,
    vault_dir: Path,
    acting_user_id: int,
    action: str = "DOWNLOAD",
) -> Tuple[bytes, str, str]:
    """
    Stream-decrypt an evidence file, verifying its SHA-256 against stored fingerprint.
    If intact: logs VIEW/DOWNLOAD, updates last_verified_at, returns (decrypted_bytes, display_name, mime_real).
    If compromised: marks COMPROMISED, logs VERIFY_FAIL, raises ValueError.
    """
    row = query_db(
        """
        SELECT id, case_id, display_name, stored_name, size, mime_real, sha256,
               integrity_status, withdrawn
        FROM evidence WHERE id = ?
        """,
        (evidence_id,),
        one=True,
    )
    if not row:
        raise ValueError("Evidence not found.")

    vault_path = vault_dir / row["stored_name"]
    if not vault_path.is_file():
        raise FileNotFoundError(f"Vault file missing on disk: {row['stored_name']}")

    # Stream-decrypt and compute SHA-256
    sha256_hasher = hashlib.sha256()
    decrypted_chunks: List[bytes] = []

    try:
        for chunk in decrypt_stream_aes_gcm_chunked(vault_path):
            sha256_hasher.update(chunk)
            decrypted_chunks.append(chunk)
    except Exception as e:
        # Decryption or authentication tag failed
        execute_db(
            "UPDATE evidence SET integrity_status = 'COMPROMISED' WHERE id = ?",
            (evidence_id,),
        )
        custody_append(
            case_id=row["case_id"],
            evidence_id=evidence_id,
            user_id=acting_user_id,
            action="VERIFY_FAIL",
            detail={"error": "GCM auth tag verification failure"},
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
        )
        raise ValueError(f"Cryptographic integrity compromised: {e}")

    computed_hash = sha256_hasher.hexdigest()
    now_utc = datetime.now(timezone.utc).isoformat()

    if computed_hash != row["sha256"]:
        # Hash mismatch! Mark compromised
        execute_db(
            "UPDATE evidence SET integrity_status = 'COMPROMISED' WHERE id = ?",
            (evidence_id,),
        )
        custody_append(
            case_id=row["case_id"],
            evidence_id=evidence_id,
            user_id=acting_user_id,
            action="VERIFY_FAIL",
            detail={"expected_sha256": row["sha256"], "computed_sha256": computed_hash},
            timestamp_utc=now_utc,
        )
        raise ValueError(
            f"Integrity check FAILED: Computed SHA-256 ({computed_hash}) does not match stored hash ({row['sha256']})."
        )

    # Hash verified: update last_verified_at and log access
    execute_db(
        "UPDATE evidence SET last_verified_at = ? WHERE id = ?",
        (now_utc, evidence_id),
    )
    custody_append(
        case_id=row["case_id"],
        evidence_id=evidence_id,
        user_id=acting_user_id,
        action=action,
        detail={"sha256": computed_hash},
        timestamp_utc=now_utc,
    )

    return b"".join(decrypted_chunks), row["display_name"], row["mime_real"]


def list_evidence_for_case(
    case_id: int,
    query_str: Optional[str] = None,
    tag_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all evidence records for a case with filtering."""
    sql = """
        SELECT e.id, e.case_id, e.display_name, e.stored_name, e.size, e.mime_real,
               e.sha256, e.integrity_status, e.source_type, e.tags, e.notes,
               e.withdrawn, e.withdrawn_reason, e.uploaded_at, e.last_verified_at,
               u.name AS uploader_name
        FROM evidence e
        JOIN users u ON e.uploaded_by = u.id
        WHERE e.case_id = ?
    """
    params: List[Any] = [case_id]

    if query_str:
        sql += " AND (e.display_name LIKE ? OR e.sha256 LIKE ? OR e.tags LIKE ?)"
        q = f"%{query_str.strip()}%"
        params.extend([q, q, q])

    if tag_filter:
        sql += " AND e.tags LIKE ?"
        params.append(f"%{tag_filter.strip()}%")

    if status_filter and status_filter != "All":
        sql += " AND e.integrity_status = ?"
        params.append(status_filter)

    sql += " ORDER BY e.id DESC"
    rows = query_db(sql, tuple(params))
    return [dict(r) for r in rows]


def get_evidence_details(evidence_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve full evidence metadata."""
    row = query_db(
        """
        SELECT e.id, e.case_id, e.display_name, e.stored_name, e.size, e.mime_real,
               e.sha256, e.integrity_status, e.source_type, e.tags, e.notes,
               e.withdrawn, e.withdrawn_reason, e.uploaded_at, e.last_verified_at,
               u.name AS uploader_name, c.case_no, c.title AS case_title, c.legal_hold
        FROM evidence e
        JOIN users u ON e.uploaded_by = u.id
        JOIN cases c ON e.case_id = c.id
        WHERE e.id = ?
        """,
        (evidence_id,),
        one=True,
    )
    return dict(row) if row else None


def get_evidence_custody_history(evidence_id: int) -> List[Dict[str, Any]]:
    """Retrieve audit history specifically related to this evidence item."""
    rows = query_db(
        """
        SELECT c.id, c.action, c.detail_json, c.timestamp_utc, c.entry_hash, u.name AS user_name
        FROM custody_log c
        LEFT JOIN users u ON c.user_id = u.id
        WHERE c.evidence_id = ?
        ORDER BY c.id DESC
        """,
        (evidence_id,),
    )
    return [dict(r) for r in rows]


def update_evidence_metadata(
    evidence_id: int,
    tags: str,
    notes: str,
    acting_user_id: int,
) -> None:
    """Update editable tags and analyst notes. Changes are audited in custody log."""
    old_row = query_db("SELECT case_id, tags, notes FROM evidence WHERE id = ?", (evidence_id,), one=True)
    if not old_row:
        raise ValueError("Evidence not found.")

    execute_db(
        "UPDATE evidence SET tags = ?, notes = ? WHERE id = ?",
        (tags.strip(), notes.strip(), evidence_id),
    )

    custody_append(
        case_id=old_row["case_id"],
        evidence_id=evidence_id,
        user_id=acting_user_id,
        action="METADATA_UPDATE",
        detail={"old_tags": old_row["tags"], "new_tags": tags.strip(), "notes_updated": 1},
    )


def withdraw_evidence(
    evidence_id: int,
    reason: str,
    acting_user_id: int,
) -> None:
    """
    Mark an evidence item as withdrawn. Lead role only.
    Strictly blocked if the parent case is under Legal Hold!
    Evidence is NEVER deleted from the vault or database.
    """
    clean_reason = reason.strip()
    if not clean_reason:
        raise ValueError("A formal reason is strictly required to withdraw evidence.")

    row = query_db(
        """
        SELECT e.case_id, e.withdrawn, c.legal_hold, c.lead_user_id
        FROM evidence e
        JOIN cases c ON e.case_id = c.id
        WHERE e.id = ?
        """,
        (evidence_id,),
        one=True,
    )
    if not row:
        raise ValueError("Evidence not found.")

    if row["lead_user_id"] != acting_user_id:
        raise PermissionError("Only the case lead can withdraw evidence.")

    if row["legal_hold"]:
        raise PermissionError("Evidence withdrawal is strictly forbidden while Legal Hold is active.")

    if row["withdrawn"]:
        raise ValueError("Evidence has already been withdrawn.")

    execute_db(
        "UPDATE evidence SET withdrawn = 1, withdrawn_reason = ? WHERE id = ?",
        (clean_reason, evidence_id),
    )

    custody_append(
        case_id=row["case_id"],
        evidence_id=evidence_id,
        user_id=acting_user_id,
        action="WITHDRAW",
        detail={"reason": clean_reason},
    )
