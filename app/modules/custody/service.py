"""
ForensiX Chain-of-Custody Service.
The ONLY authoritative writer for custody_log.
Implements hash-chained immutable audit logging, canonical JSON formatting,
thread-safe serialized appending, and mathematical chain verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.db import query_db, execute_db
from app.security.crypto import compute_custody_hmac

# Process-wide reentrant lock to serialize append operations and prevent chain forks
_CHAIN_LOCK = threading.RLock()
GENESIS_PREV_HASH = "0" * 64


def canonical_json(
    case_id: Optional[int],
    evidence_id: Optional[int],
    user_id: Optional[int],
    action: str,
    detail: Dict[str, Any],
    timestamp_utc: str,
) -> str:
    """
    Produce canonical, deterministic JSON representation for cryptographic hashing.
    Keys are strictly sorted with compact separators.
    """
    payload = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "user_id": user_id,
        "action": action.strip(),
        "detail": detail if isinstance(detail, dict) else {},
        "timestamp_utc": timestamp_utc.strip(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_entry_hash(
    case_id: Optional[int],
    evidence_id: Optional[int],
    user_id: Optional[int],
    action: str,
    detail: Dict[str, Any],
    timestamp_utc: str,
    prev_hash: str,
) -> str:
    """
    Compute SHA-256(canonical_json(...) + prev_hash).
    """
    canon_str = canonical_json(
        case_id=case_id,
        evidence_id=evidence_id,
        user_id=user_id,
        action=action,
        detail=detail,
        timestamp_utc=timestamp_utc,
    )
    hasher = hashlib.sha256()
    hasher.update((canon_str + prev_hash).encode("utf-8"))
    return hasher.hexdigest()


def append(
    case_id: Optional[int],
    evidence_id: Optional[int],
    user_id: Optional[int],
    action: str,
    detail: Optional[Dict[str, Any]] = None,
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Append an entry to the custody log.
    This is the ONLY function permitted to insert into custody_log.
    Runs inside a thread lock and single transaction to prevent chain forking.
    """
    clean_detail = detail if isinstance(detail, dict) else {}
    ts = timestamp_utc or datetime.now(timezone.utc).isoformat()

    with _CHAIN_LOCK:
        # Determine previous hash in this specific chain
        if case_id is not None:
            last_row = query_db(
                "SELECT entry_hash FROM custody_log WHERE case_id = ? ORDER BY id DESC LIMIT 1",
                (case_id,),
                one=True,
            )
        else:
            last_row = query_db(
                "SELECT entry_hash FROM custody_log WHERE case_id IS NULL ORDER BY id DESC LIMIT 1",
                (),
                one=True,
            )

        prev_hash = last_row["entry_hash"] if last_row else GENESIS_PREV_HASH

        entry_hash = compute_entry_hash(
            case_id=case_id,
            evidence_id=evidence_id,
            user_id=user_id,
            action=action,
            detail=clean_detail,
            timestamp_utc=ts,
            prev_hash=prev_hash,
        )

        entry_hmac = compute_custody_hmac(entry_hash)
        detail_json_str = json.dumps(clean_detail, sort_keys=True)

        entry_id = execute_db(
            """
            INSERT INTO custody_log (case_id, evidence_id, user_id, action, detail_json, timestamp_utc, prev_hash, entry_hash, entry_hmac)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (case_id, evidence_id, user_id, action.strip(), detail_json_str, ts, prev_hash, entry_hash, entry_hmac),
        )

        return {
            "id": entry_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "user_id": user_id,
            "action": action.strip(),
            "detail": clean_detail,
            "timestamp_utc": ts,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "entry_hmac": entry_hmac,
        }


def verify_chain(case_id: Optional[int]) -> Dict[str, Any]:
    """
    Walk and verify the custody chain from the genesis entry to the head.
    Returns:
      {"status": "OK", "entries_count": N, "head_hash": "..."}
      or
      {"status": "BROKEN", "broken_at_entry": ID, "sequence": N, "reason": "..."}
    """
    with _CHAIN_LOCK:
        if case_id is not None:
            rows = query_db(
                """
                SELECT id, case_id, evidence_id, user_id, action, detail_json,
                       timestamp_utc, prev_hash, entry_hash, entry_hmac
                FROM custody_log
                WHERE case_id = ?
                ORDER BY id ASC
                """,
                (case_id,),
            )
        else:
            rows = query_db(
                """
                SELECT id, case_id, evidence_id, user_id, action, detail_json,
                       timestamp_utc, prev_hash, entry_hash, entry_hmac
                FROM custody_log
                WHERE case_id IS NULL
                ORDER BY id ASC
                """,
                (),
            )

        entries = [dict(r) for r in rows]
        if not entries:
            return {
                "status": "OK",
                "entries_count": 0,
                "head_hash": GENESIS_PREV_HASH,
                "message": "Chain is empty (intact).",
            }

        expected_prev_hash = GENESIS_PREV_HASH

        for idx, entry in enumerate(entries, start=1):
            # 1. Verify linkage to previous entry hash
            if entry["prev_hash"] != expected_prev_hash:
                return {
                    "status": "BROKEN",
                    "broken_at_entry": entry["id"],
                    "sequence": idx,
                    "reason": f"Chain linkage broken: prev_hash does not match preceding entry hash.",
                    "expected_prev_hash": expected_prev_hash,
                    "actual_prev_hash": entry["prev_hash"],
                }

            # 2. Parse detail JSON
            try:
                detail_dict = json.loads(entry["detail_json"]) if entry["detail_json"] else {}
            except Exception:
                detail_dict = {}

            # 3. Recompute cryptographic entry hash
            recomputed_hash = compute_entry_hash(
                case_id=entry["case_id"],
                evidence_id=entry["evidence_id"],
                user_id=entry["user_id"],
                action=entry["action"],
                detail=detail_dict,
                timestamp_utc=entry["timestamp_utc"],
                prev_hash=entry["prev_hash"],
            )

            if recomputed_hash != entry["entry_hash"]:
                return {
                    "status": "BROKEN",
                    "broken_at_entry": entry["id"],
                    "sequence": idx,
                    "reason": f"Content integrity broken: entry_hash does not match recomputed SHA-256.",
                    "expected_hash": recomputed_hash,
                    "actual_hash": entry["entry_hash"],
                }

            # 4. Verify HMAC-SHA256 signature if stored (C3)
            stored_hmac = entry.get("entry_hmac")
            if stored_hmac:
                expected_hmac = compute_custody_hmac(entry["entry_hash"])
                if not hmac.compare_digest(stored_hmac, expected_hmac):
                    return {
                        "status": "BROKEN",
                        "broken_at_entry": entry["id"],
                        "sequence": idx,
                        "reason": "HMAC integrity broken: entry_hmac does not match master key derivation.",
                        "expected_hmac": expected_hmac,
                        "actual_hmac": stored_hmac,
                    }

            # Advance expected previous hash for next iteration
            expected_prev_hash = entry["entry_hash"]

        return {
            "status": "OK",
            "entries_count": len(entries),
            "head_hash": expected_prev_hash,
            "message": f"Chain intact, {len(entries)} entries.",
        }


def get_custody_entries(
    case_id: Optional[int],
    action_filter: Optional[str] = None,
    user_filter: Optional[int] = None,
    evidence_filter: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Retrieve custody log records with filtering."""
    sql = """
        SELECT c.id, c.case_id, c.evidence_id, c.user_id, c.action, c.detail_json,
               c.timestamp_utc, c.prev_hash, c.entry_hash,
               u.name AS user_name, u.username,
               e.display_name AS evidence_name
        FROM custody_log c
        LEFT JOIN users u ON c.user_id = u.id
        LEFT JOIN evidence e ON c.evidence_id = e.id
        WHERE 1=1
    """
    params: List[Any] = []

    if case_id is not None:
        sql += " AND c.case_id = ?"
        params.append(case_id)
    else:
        sql += " AND c.case_id IS NULL"

    if action_filter and action_filter != "All":
        sql += " AND c.action = ?"
        params.append(action_filter)

    if user_filter:
        sql += " AND c.user_id = ?"
        params.append(user_filter)

    if evidence_filter:
        sql += " AND c.evidence_id = ?"
        params.append(evidence_filter)

    sql += " ORDER BY c.id DESC"
    rows = query_db(sql, tuple(params))
    return [dict(r) for r in rows]
