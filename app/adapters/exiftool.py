"""
ForensiX ExifTool Adapter.
Executes Phil Harvey's ExifTool via the S6 subprocess containment engine
to extract raw metadata, EXIF, XMP, IPTC, and camera tags.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from app.adapters.base import run_tool
from app.adapters.registry import is_tool_available

logger = logging.getLogger("forensix")


def extract_exiftool_metadata(
    case_id: int,
    evidence_id: int,
    acting_user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run ExifTool on the specified evidence item with JSON output format.
    Returns:
      {
        "available": bool,
        "success": bool,
        "tags": Dict[str, Any],
        "error": Optional[str],
      }
    """
    if not is_tool_available("exiftool"):
        return {
            "available": False,
            "success": False,
            "tags": {},
            "error": "ExifTool executable is not available on this system.",
        }

    # -json emits structured JSON; -n disables print conversion (raw numeric values e.g. for GPS)
    res = run_tool(
        tool_key="exiftool",
        args=["-json", "-n", "{input_file}"],
        case_id=case_id,
        input_evidence_id=evidence_id,
        timeout=30,
        acting_user_id=acting_user_id,
    )

    if res["status"] != "done" or res["returncode"] != 0:
        return {
            "available": True,
            "success": False,
            "tags": {},
            "error": res.get("error") or res.get("stderr") or "ExifTool exited with non-zero status.",
        }

    try:
        data = json.loads(res["stdout"])
        tags = data[0] if isinstance(data, list) and len(data) > 0 else {}
        return {
            "available": True,
            "success": True,
            "tags": tags,
            "error": None,
        }
    except Exception as e:
        logger.warning(f"Failed to parse ExifTool JSON output for evidence #{evidence_id}: {e}")
        return {
            "available": True,
            "success": False,
            "tags": {},
            "error": f"JSON parsing failed: {e}",
        }
