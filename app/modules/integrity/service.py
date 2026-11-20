"""
ForensiX Evidence Integrity Verification Service.
Implements on-demand and scheduled cryptographic re-verification of evidence files.
Mismatches trigger COMPROMISED status and log VERIFY_FAIL in the custody chain.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from flask import current_app

from app.db import query_db, execute_db
from app.security.crypto import decrypt_stream_aes_gcm_chunked
from app.modules.custody.service import append as custody_append


def verify_evidence(
    evidence_id: int,
    acting_user_id: Optional[int] = None,
    vault_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Stream-decrypt an evidence vault file, calculate its SHA-256 hash,
    and compare against the recorded intake fingerprint.
    """
    row = query_db(
        """
        SELECT id, case_id, display_name, stored_name, size, sha256,
               integrity_status, withdrawn
        FROM evidence WHERE id = ?
        """,
        (evidence_id,),
        one=True,
    )
    if not row:
        return {"status": "ERROR", "error": "Evidence item not found."}

    if vault_dir is None:
        vault_dir = Path(current_app.config["VAULT_DIR"])

    vault_path = vault_dir / row["stored_name"]
    if not vault_path.is_file():
        now_utc = datetime.now(timezone.utc).isoformat()
        execute_db("UPDATE evidence SET integrity_status = 'COMPROMISED' WHERE id = ?", (evidence_id,))
        custody_append(
            case_id=row["case_id"],
            evidence_id=evidence_id,
            user_id=acting_user_id,
            action="VERIFY_FAIL",
            detail={"error": "Vault file missing on physical storage"},
            timestamp_utc=now_utc,
        )
        return {"status": "COMPROMISED", "error": "Vault file missing on disk."}

    sha256_hasher = hashlib.sha256()

    try:
        for chunk in decrypt_stream_aes_gcm_chunked(vault_path):
            sha256_hasher.update(chunk)
    except Exception as e:
        now_utc = datetime.now(timezone.utc).isoformat()
        execute_db("UPDATE evidence SET integrity_status = 'COMPROMISED' WHERE id = ?", (evidence_id,))
        custody_append(
            case_id=row["case_id"],
            evidence_id=evidence_id,
            user_id=acting_user_id,
            action="VERIFY_FAIL",
            detail={"error": f"Decryption/GCM authentication error: {str(e)}"},
            timestamp_utc=now_utc,
        )
        return {"status": "COMPROMISED", "error": f"Decryption failure: {str(e)}"}

    computed_hash = sha256_hasher.hexdigest()
    now_utc = datetime.now(timezone.utc).isoformat()

    if computed_hash != row["sha256"]:
        # Tampered or corrupted! Mark COMPROMISED
        execute_db("UPDATE evidence SET integrity_status = 'COMPROMISED' WHERE id = ?", (evidence_id,))
        custody_append(
            case_id=row["case_id"],
            evidence_id=evidence_id,
            user_id=acting_user_id,
            action="VERIFY_FAIL",
            detail={"expected_sha256": row["sha256"], "computed_sha256": computed_hash},
            timestamp_utc=now_utc,
        )
        return {
            "status": "COMPROMISED",
            "evidence_id": evidence_id,
            "display_name": row["display_name"],
            "expected_sha256": row["sha256"],
            "computed_sha256": computed_hash,
        }

    # Intact: update last_verified_at and log VERIFY_OK
    execute_db("UPDATE evidence SET last_verified_at = ? WHERE id = ?", (now_utc, evidence_id))
    custody_append(
        case_id=row["case_id"],
        evidence_id=evidence_id,
        user_id=acting_user_id,
        action="VERIFY_OK",
        detail={"sha256": computed_hash},
        timestamp_utc=now_utc,
    )

    return {
        "status": "VERIFIED",
        "evidence_id": evidence_id,
        "display_name": row["display_name"],
        "sha256": computed_hash,
    }


def verify_all_case_evidence(case_id: int, acting_user_id: Optional[int] = None) -> Dict[str, Any]:
    """Re-verify all active evidence files in a case."""
    rows = query_db(
        "SELECT id FROM evidence WHERE case_id = ? AND withdrawn = 0 ORDER BY id ASC",
        (case_id,),
    )
    results = []
    compromised_count = 0

    for r in rows:
        res = verify_evidence(r["id"], acting_user_id=acting_user_id)
        results.append(res)
        if res["status"] == "COMPROMISED":
            compromised_count += 1

    return {
        "total": len(rows),
        "compromised_count": compromised_count,
        "intact_count": len(rows) - compromised_count,
        "results": results,
    }
