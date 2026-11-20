"""
ForensiX External Tool Registry.
Detects, validates, and manages external CLI forensic utilities (tshark, capinfos, exiftool).
Gracefully degrades features when an external tool is not installed or available.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from flask import current_app

logger = logging.getLogger("forensix")

# Registry dictionary caching detected status and metadata:
# tool_key -> {
#   "name": display_name,
#   "configured_path": path_str,
#   "resolved_path": absolute_or_cmd_str or None,
#   "available": bool,
#   "version": version_str or None,
#   "error": error_str or None,
#   "description": str,
#   "version_args": list[str],
# }
_TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {}


def register_tool(
    tool_key: str,
    name: str,
    configured_path: str,
    description: str = "",
    version_args: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Register or update an external tool in the platform registry."""
    v_args = version_args if version_args is not None else ["--version"]

    resolved: Optional[str] = None
    available = False
    version: Optional[str] = None
    error_msg: Optional[str] = None

    # Check path existence or search system PATH
    p = Path(configured_path)
    if p.is_file() and os.access(str(p), os.X_OK if os.name != "nt" else os.R_OK):
        resolved = str(p.resolve())
    else:
        which_result = shutil.which(configured_path)
        if which_result:
            resolved = which_result

    # Fallback to standard installation directories on Windows
    if not resolved and os.name == "nt":
        common_locations = {
            "tshark": [
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe",
            ],
            "capinfos": [
                r"C:\Program Files\Wireshark\capinfos.exe",
                r"C:\Program Files (x86)\Wireshark\capinfos.exe",
            ],
            "exiftool": [
                Path.home() / "AppData" / "Local" / "Programs" / "ExifTool" / "ExifTool.exe",
                Path.home() / "AppData" / "Local" / "Programs" / "ExifTool" / "exiftool.exe",
                r"C:\Program Files\exiftool\exiftool.exe",
            ],
            "fls": [
                Path.home() / "AppData" / "Local" / "Programs" / "sleuthkit" / "bin" / "fls.exe",
                Path.home() / "AppData" / "Local" / "Programs" / "sleuthkit" / "sleuthkit-4.15.0-win32" / "bin" / "fls.exe",
                r"C:\Program Files\sleuthkit\bin\fls.exe",
                r"C:\Program Files\Autopsy\autopsy\sleuthkit\bin\fls.exe",
            ],
        }
        for loc in common_locations.get(tool_key, []):
            loc_p = Path(loc)
            if loc_p.is_file():
                resolved = str(loc_p.resolve())
                break

    if resolved:
        try:
            # Safe probe without shell=True
            res = subprocess.run(
                [resolved] + v_args,
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            raw_out = (res.stdout or res.stderr or "").strip()
            # Extract first line for version string
            lines = [ln.strip() for ln in raw_out.splitlines() if ln.strip()]
            version = lines[0] if lines else "Version unknown"
            available = True
        except subprocess.TimeoutExpired:
            error_msg = "Version detection timed out after 5 seconds."
        except Exception as e:
            error_msg = f"Failed to execute binary: {e}"
    else:
        error_msg = f"Binary '{configured_path}' not found on PATH or specified location."

    info = {
        "key": tool_key,
        "name": name,
        "configured_path": configured_path,
        "resolved_path": resolved,
        "available": available,
        "version": version,
        "error": error_msg,
        "description": description,
        "version_args": v_args,
    }
    _TOOL_REGISTRY[tool_key] = info
    return info


def init_tool_registry(app=None) -> Dict[str, Dict[str, Any]]:
    """Initialize standard forensic tools using paths from app config or environment."""
    tshark_path = "tshark"
    capinfos_path = "capinfos"
    exiftool_path = "exiftool"
    fls_path = "fls"

    if app is not None:
        tshark_path = app.config.get("TSHARK_PATH", "tshark")
        capinfos_path = app.config.get("CAPINFOS_PATH", "capinfos")
        exiftool_path = app.config.get("EXIFTOOL_PATH", "exiftool")
        fls_path = app.config.get("FLS_PATH", "fls")

    register_tool(
        tool_key="tshark",
        name="Wireshark TShark",
        configured_path=tshark_path,
        description="Command-line packet capture and network protocol dissection engine.",
        version_args=["-v"],
    )

    register_tool(
        tool_key="capinfos",
        name="Wireshark Capinfos",
        configured_path=capinfos_path,
        description="Packet capture metadata, interface summary, and statistical analyzer.",
        version_args=["-v"],
    )

    register_tool(
        tool_key="exiftool",
        name="Phil Harvey's ExifTool",
        configured_path=exiftool_path,
        description="Deep file metadata, EXIF, XMP, IPTC, and camera tag extractor.",
        version_args=["-ver"],
    )

    register_tool(
        tool_key="fls",
        name="The Sleuth Kit (fls)",
        configured_path=fls_path,
        description="Lists file and directory names in disk images, partitions, and file systems.",
        version_args=["-V"],
    )

    return _TOOL_REGISTRY


def get_tool_info(tool_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve metadata and availability for a registered tool."""
    return _TOOL_REGISTRY.get(tool_key)


def is_tool_available(tool_key: str) -> bool:
    """Check if a registered tool is verified available for execution."""
    info = _TOOL_REGISTRY.get(tool_key)
    return bool(info and info.get("available"))


def get_tool_executable(tool_key: str) -> Optional[str]:
    """Get the resolved executable binary path for a tool."""
    info = _TOOL_REGISTRY.get(tool_key)
    if info and info.get("available"):
        return info.get("resolved_path")
    return None


def list_all_tools() -> List[Dict[str, Any]]:
    """Return all registered tools as a list."""
    return list(_TOOL_REGISTRY.values())
