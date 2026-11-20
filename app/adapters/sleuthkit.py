"""
ForensiX The Sleuth Kit (TSK) Adapter.
Executes fls from The Sleuth Kit via the S6 subprocess containment engine
to safely list directory structures, allocated and unallocated files in disk images.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from app.adapters.base import run_tool
from app.adapters.registry import is_tool_available

logger = logging.getLogger("forensix")

# Regex to parse standard fls output lines:
# Examples:
#   d/d 144-144-1: /evidence_dir
#   r/r 128-128-3: /evidence_dir/passwords.txt
#   r/r * 129-128-3: /evidence_dir/deleted_secret.doc (asterisk indicates deleted file)
FLS_LINE_RE = re.compile(r"^([a-z\*\-/]+)\s+(\*?\s*\S+):\s+(.+)$")


def list_disk_image_files(
    case_id: int,
    evidence_id: int,
    acting_user_id: Optional[int] = None,
    recursive: bool = True,
) -> Dict[str, Any]:
    """
    Run fls on a disk image evidence item (raw, dd, iso, or E01).
    Safely sandboxed via the S6 adapter execution engine with timeout and output cap.

    Returns:
      {
        "available": bool,
        "success": bool,
        "entries": List[Dict[str, Any]],
        "error": Optional[str],
      }
    """
    if not is_tool_available("fls"):
        return {
            "available": False,
            "success": False,
            "entries": [],
            "error": "The Sleuth Kit (fls) is not installed or available on this system.",
        }

    args = ["-p"]
    if recursive:
        args.append("-r")
    args.append("{input_file}")

    res = run_tool(
        tool_key="fls",
        args=args,
        case_id=case_id,
        input_evidence_id=evidence_id,
        timeout=45,
        acting_user_id=acting_user_id,
    )

    if res.get("status") != "done" or res.get("returncode") != 0:
        return {
            "available": True,
            "success": False,
            "entries": [],
            "error": res.get("error") or res.get("stderr") or "fls exited with non-zero status.",
        }

    raw_output = res.get("stdout", "")
    if isinstance(raw_output, bytes):
        raw_output = raw_output.decode("utf-8", errors="replace")

    entries: List[Dict[str, Any]] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        match = FLS_LINE_RE.match(line)
        if match:
            type_flags, inode, file_path = match.groups()
            is_deleted = "*" in type_flags or "*" in inode
            primary_type = "directory" if type_flags.startswith("d") else "file"
            entries.append({
                "type": primary_type,
                "flags": type_flags.strip(),
                "inode": inode.replace("*", "").strip(),
                "path": file_path.strip(),
                "is_deleted": is_deleted,
            })
        else:
            entries.append({
                "type": "raw",
                "raw": line,
            })

    return {
        "available": True,
        "success": True,
        "entries": entries,
        "error": None,
    }
