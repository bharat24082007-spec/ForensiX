"""
ForensiX TShark & Capinfos Network Tool Adapters.
Executes Wireshark CLI binaries (tshark, capinfos) through the S6 subprocess
containment engine to dissect packet captures into structured text records.
Enforces hard packet caps, execution timeouts, and strict field parameterization.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any, Dict, List, Optional
from app.adapters.base import run_tool
from app.adapters.registry import is_tool_available, get_tool_info

logger = logging.getLogger("forensix")


def run_capinfos(
    case_id: int,
    evidence_id: int,
    acting_user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute capinfos on a pcap evidence file to extract high-level capture statistics.
    Returns:
      {
        "available": bool,
        "success": bool,
        "packet_count": Optional[int],
        "start_time": Optional[str],
        "end_time": Optional[str],
        "duration": Optional[str],
        "raw_output": str,
        "error": Optional[str],
      }
    """
    if not is_tool_available("capinfos"):
        return {
            "available": False,
            "success": False,
            "packet_count": None,
            "start_time": None,
            "end_time": None,
            "duration": None,
            "raw_output": "",
            "error": "Capinfos utility is not available on this system.",
        }

    res = run_tool(
        tool_key="capinfos",
        args=["{input_file}"],
        case_id=case_id,
        input_evidence_id=evidence_id,
        timeout=20,
        acting_user_id=acting_user_id,
    )

    if res["status"] != "done" or res["returncode"] != 0:
        return {
            "available": True,
            "success": False,
            "packet_count": None,
            "start_time": None,
            "end_time": None,
            "duration": None,
            "raw_output": res.get("stderr", ""),
            "error": res.get("error") or "Capinfos exited with error.",
        }

    out = res.get("stdout", "")
    info: Dict[str, Any] = {
        "available": True,
        "success": True,
        "packet_count": None,
        "start_time": None,
        "end_time": None,
        "duration": None,
        "raw_output": out,
        "error": None,
    }

    for line in out.splitlines():
        if "Number of packets" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                try:
                    # Remove formatting commas, e.g. "1,250" -> 1250
                    info["packet_count"] = int(parts[1].strip().replace(",", "").replace("k", "000"))
                except ValueError:
                    pass
        elif "First packet time" in line:
            parts = line.split(":", 1)
            if len(parts) >= 2:
                info["start_time"] = parts[1].strip()
        elif "Last packet time" in line:
            parts = line.split(":", 1)
            if len(parts) >= 2:
                info["end_time"] = parts[1].strip()
        elif "Capture duration" in line:
            parts = line.split(":", 1)
            if len(parts) >= 2:
                info["duration"] = parts[1].strip()

    return info


def run_tshark_dissection(
    case_id: int,
    evidence_id: int,
    packet_cap: int = 200000,
    timeout: int = 45,
    acting_user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute tshark with parameterized field extraction on a packet capture.
    Extracts: frame.time_epoch, ip.src, ip.dst, tcp.dstport, udp.dstport,
              dns.qry.name, http.host, http.request.uri.
    Returns:
      {
        "available": bool,
        "status": "done" | "failed" | "unavailable",
        "records": List[Dict[str, Any]],
        "command": List[str],
        "version": str,
        "error": Optional[str],
      }
    """
    if not is_tool_available("tshark"):
        return {
            "available": False,
            "status": "unavailable",
            "records": [],
            "command": [],
            "version": "Not installed",
            "error": "TShark (Wireshark CLI) is not available or not installed on this system.",
        }

    tool_info = get_tool_info("tshark")
    version = tool_info.get("version", "Unknown") if tool_info else "Unknown"

    args = [
        "-r", "{input_file}",
        "-c", str(packet_cap),
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "dns.qry.name",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-E", "separator=,",
        "-E", "header=y",
        "-E", "occurrence=f",
    ]

    res = run_tool(
        tool_key="tshark",
        args=args,
        case_id=case_id,
        input_evidence_id=evidence_id,
        timeout=timeout,
        max_output_bytes=25 * 1024 * 1024,  # 25 MB cap for flow records
        acting_user_id=acting_user_id,
    )

    if res["status"] != "done" or res["returncode"] != 0:
        return {
            "available": True,
            "status": "failed",
            "records": [],
            "command": args,
            "version": version,
            "error": res.get("error") or res.get("stderr") or "TShark exited with non-zero return code.",
        }

    raw_csv = res.get("stdout", "").strip()
    records: List[Dict[str, Any]] = []

    if raw_csv:
        reader = csv.DictReader(io.StringIO(raw_csv))
        for row in reader:
            epoch = row.get("frame.time_epoch") or ""
            ip_src = (row.get("ip.src") or "").strip()
            ip_dst = (row.get("ip.dst") or "").strip()
            tcp_port = (row.get("tcp.dstport") or "").strip()
            udp_port = (row.get("udp.dstport") or "").strip()
            dns_qry = (row.get("dns.qry.name") or "").strip()
            http_host = (row.get("http.host") or "").strip()
            http_uri = (row.get("http.request.uri") or "").strip()

            records.append(
                {
                    "epoch": epoch,
                    "ip_src": ip_src,
                    "ip_dst": ip_dst,
                    "dst_port": tcp_port or udp_port or None,
                    "proto": "TCP" if tcp_port else "UDP" if udp_port else "IP",
                    "dns_query": dns_qry or None,
                    "http_host": http_host or None,
                    "http_uri": http_uri or None,
                }
            )

    return {
        "available": True,
        "status": "done",
        "records": records,
        "command": args,
        "version": version,
        "error": None,
    }
