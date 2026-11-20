"""
ForensiX Scheduled Integrity Watchdog.
Background APScheduler worker that routinely re-verifies every non-withdrawn
evidence item in the vault to proactively detect bit-rot, tampering, or disk corruption.
Never crashes the application; safely catches exceptions per item.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask

from app.db import query_db
from app.modules.integrity.service import verify_evidence

logger = logging.getLogger("forensix")

_WATCHDOG_LOCK = threading.Lock()
_SCHEDULER: Optional[BackgroundScheduler] = None

# Watchdog operational telemetry
_WATCHDOG_STATE: Dict[str, Any] = {
    "is_running": False,
    "last_run_at": None,
    "last_status": "PENDING",
    "last_items_checked": 0,
    "last_compromised_count": 0,
    "last_error": None,
}


def get_watchdog_state() -> Dict[str, Any]:
    """Retrieve current watchdog status and last execution telemetry."""
    return dict(_WATCHDOG_STATE)


def run_integrity_watchdog_job(app: Flask) -> Dict[str, Any]:
    """
    Execute full vault evidence verification pass across all active cases.
    Guarded by lock to prevent concurrent overlapping watchdog runs.
    """
    if not _WATCHDOG_LOCK.acquire(blocking=False):
        logger.warning("Watchdog job skipped: another verification cycle is currently active.")
        return {"status": "SKIPPED", "reason": "Job currently running"}

    try:
        _WATCHDOG_STATE["is_running"] = True
        logger.info("Forensic integrity watchdog started verification sweep.")

        items_checked = 0
        compromised_count = 0

        with app.app_context():
            rows = query_db(
                "SELECT id, case_id, display_name FROM evidence WHERE withdrawn = 0 ORDER BY id ASC"
            )
            for r in rows:
                items_checked += 1
                try:
                    res = verify_evidence(r["id"], acting_user_id=None)
                    if res.get("status") == "COMPROMISED":
                        compromised_count += 1
                        logger.critical(
                            f"WATCHDOG INTEGRITY BREACH: Evidence ID {r['id']} ({r['display_name']}) in Case {r['case_id']} is COMPROMISED!"
                        )
                except Exception as ex:
                    compromised_count += 1
                    logger.error(
                        f"Watchdog exception checking evidence ID {r['id']}: {ex}",
                        exc_info=True,
                    )

        now_utc = datetime.now(timezone.utc).isoformat()
        status_label = "COMPROMISED_DETECTED" if compromised_count > 0 else "HEALTHY"

        _WATCHDOG_STATE.update(
            {
                "last_run_at": now_utc,
                "last_status": status_label,
                "last_items_checked": items_checked,
                "last_compromised_count": compromised_count,
                "last_error": None,
            }
        )

        logger.info(
            f"Integrity watchdog sweep completed: {items_checked} items checked, {compromised_count} compromised."
        )
        return dict(_WATCHDOG_STATE)

    except Exception as e:
        logger.error(f"Fatal error in integrity watchdog runner: {e}", exc_info=True)
        _WATCHDOG_STATE["last_status"] = "ERROR"
        _WATCHDOG_STATE["last_error"] = str(e)
        return dict(_WATCHDOG_STATE)

    finally:
        _WATCHDOG_STATE["is_running"] = False
        _WATCHDOG_LOCK.release()


def init_watchdog(app: Flask, interval_minutes: int = 60) -> Optional[BackgroundScheduler]:
    """Initialize in-process APScheduler background watchdog."""
    global _SCHEDULER

    # In testing mode without scheduler needed, or if already started, return existing
    if app.config.get("TESTING") and not app.config.get("ENABLE_WATCHDOG_SCHEDULER"):
        return None

    if _SCHEDULER is not None and _SCHEDULER.running:
        return _SCHEDULER

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=run_integrity_watchdog_job,
        args=[app],
        trigger="interval",
        minutes=interval_minutes,
        id="forensix_integrity_watchdog",
        name="ForensiX Evidence Integrity Watchdog",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=300,
    )
    scheduler.start()
    _SCHEDULER = scheduler
    logger.info(f"Integrity watchdog scheduled: runs every {interval_minutes} minutes.")
    return _SCHEDULER
