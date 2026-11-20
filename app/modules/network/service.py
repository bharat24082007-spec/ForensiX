"""
ForensiX Network Packet Analysis Service.
Coordinates packet dissection using TShark and Capinfos (via S6 engine)
with an in-memory native PCAP parser fallback for environments without Wireshark.
Generates:
- Network timeline events (events table with source_type='pcap')
- Network indicators of compromise (iocs table: IP, Domain, URL)
- Forensic heuristic findings: Port scans, DNS spikes, rare external connections
"""

from __future__ import annotations

import io
import re
import socket
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.db import query_db, execute_db
from app.modules.evidence.service import get_evidence_details, verify_and_decrypt_evidence
from app.adapters.tshark import run_tshark_dissection, run_capinfos
from app.adapters.registry import is_tool_available, get_tool_info


def is_private_ip(ip_str: str) -> bool:
    """Check if an IPv4 address belongs to private/loopback RFC-1918 subnets."""
    if not ip_str or ":" in ip_str:
        return False
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        b0, b1 = int(parts[0]), int(parts[1])
        if b0 == 10:
            return True
        if b0 == 127:
            return True
        if b0 == 192 and b1 == 168:
            return True
        if b0 == 172 and 16 <= b1 <= 31:
            return True
        if b0 == 0 or b0 >= 224:
            return True
        return False
    except ValueError:
        return False


def parse_pcap_in_memory(pcap_bytes: bytes, max_packets: int = 50000) -> List[Dict[str, Any]]:
    """
    Native fallback PCAP packet reader for standard libpcap binary captures.
    Safely dissects IPv4, TCP, UDP, DNS queries, and HTTP requests directly in memory.
    """
    records: List[Dict[str, Any]] = []
    if len(pcap_bytes) < 24:
        return records

    magic = pcap_bytes[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"  # Little-endian
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"  # Big-endian
    else:
        # Not a classic libpcap file (could be pcapng or raw stream)
        return records

    offset = 24  # Skip 24-byte global header
    total_len = len(pcap_bytes)
    pkt_count = 0

    while offset + 16 <= total_len and pkt_count < max_packets:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pcap_bytes[offset:offset+16])
        offset += 16
        if offset + incl_len > total_len:
            break

        pkt_data = pcap_bytes[offset:offset+incl_len]
        offset += incl_len
        pkt_count += 1

        # Check Ethernet frame (14 bytes)
        if len(pkt_data) < 34:
            continue
        eth_type = struct.unpack("!H", pkt_data[12:14])[0]
        if eth_type != 0x0800:
            continue  # Only IPv4

        ip_hdr = pkt_data[14:]
        if len(ip_hdr) < 20:
            continue

        ihl = (ip_hdr[0] & 0x0F) * 4
        proto_num = ip_hdr[9]
        src_ip = socket.inet_ntoa(ip_hdr[12:16])
        dst_ip = socket.inet_ntoa(ip_hdr[16:20])

        proto = "IP"
        dst_port = None
        dns_qry = None
        http_host = None
        http_uri = None

        epoch_str = f"{ts_sec}.{ts_usec:06d}"

        if proto_num == 6 and len(ip_hdr) >= ihl + 20:  # TCP
            proto = "TCP"
            tcp_hdr = ip_hdr[ihl:]
            dst_port = str(struct.unpack("!H", tcp_hdr[2:4])[0])
            tcp_offset = ((tcp_hdr[12] >> 4) & 0x0F) * 4
            tcp_payload = tcp_hdr[tcp_offset:]
            if len(tcp_payload) > 10 and (tcp_payload.startswith(b"GET ") or tcp_payload.startswith(b"POST ") or tcp_payload.startswith(b"HEAD ")):
                try:
                    head_text = tcp_payload[:500].decode("latin1", errors="ignore")
                    lines = head_text.split("\r\n")
                    first_line = lines[0].split(" ")
                    if len(first_line) >= 2:
                        http_uri = first_line[1]
                    for ln in lines[1:]:
                        if ln.lower().startswith("host:"):
                            http_host = ln.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass

        elif proto_num == 17 and len(ip_hdr) >= ihl + 8:  # UDP
            proto = "UDP"
            udp_hdr = ip_hdr[ihl:]
            src_port = struct.unpack("!H", udp_hdr[0:2])[0]
            dst_port_int = struct.unpack("!H", udp_hdr[2:4])[0]
            dst_port = str(dst_port_int)

            # Check DNS (port 53)
            if (dst_port_int == 53 or src_port == 53) and len(udp_hdr) > 20:
                dns_payload = udp_hdr[8:]
                try:
                    # Parse standard DNS question name
                    q_offset = 12
                    parts = []
                    while q_offset < len(dns_payload):
                        length = dns_payload[q_offset]
                        if length == 0:
                            break
                        if length > 63:
                            break
                        q_offset += 1
                        part = dns_payload[q_offset:q_offset+length].decode("latin1", errors="ignore")
                        parts.append(part)
                        q_offset += length
                    if parts:
                        dns_qry = ".".join(parts).lower()
                except Exception:
                    pass

        records.append(
            {
                "epoch": epoch_str,
                "ip_src": src_ip,
                "ip_dst": dst_ip,
                "dst_port": dst_port,
                "proto": proto,
                "dns_query": dns_qry,
                "http_host": http_host,
                "http_uri": http_uri,
            }
        )

    return records


def analyze_network_evidence(
    case_id: int,
    evidence_id: int,
    packet_cap: int = 200000,
    acting_user_id: Optional[int] = None,
    vault_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Execute full network traffic dissection pipeline on a pcap/pcapng evidence item.
    Populates:
    - events (timeline entries)
    - iocs (IP, domain, URL records)
    - findings (port scans, DNS spikes, external connection heuristics)
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
        action="NETWORK_ANALYSIS",
    )

    tshark_active = is_tool_available("tshark")
    capinfos_active = is_tool_available("capinfos")

    tool_used = "TShark" if tshark_active else "ForensiX In-Memory PCAP Engine"
    tool_version = "Native"
    tool_cmd = []

    records: List[Dict[str, Any]] = []
    cap_info: Dict[str, Any] = {}

    if tshark_active:
        t_info = get_tool_info("tshark")
        tool_version = t_info.get("version", "Unknown") if t_info else "Unknown"
        tshark_res = run_tshark_dissection(case_id, evidence_id, packet_cap=packet_cap, acting_user_id=acting_user_id)
        if tshark_res.get("status") == "done":
            records = tshark_res.get("records", [])
            tool_cmd = tshark_res.get("command", [])

        if capinfos_active:
            cap_info = run_capinfos(case_id, evidence_id, acting_user_id=acting_user_id)

    # If tshark was unavailable or produced no records, execute native in-memory parser
    if not records:
        records = parse_pcap_in_memory(evidence_bytes, max_packets=packet_cap)

    # 2. Extract Artifacts, Top Talkers, and Statistics
    src_ip_counter: Counter = Counter()
    dst_ip_counter: Counter = Counter()
    dns_query_counter: Counter = Counter()
    dst_port_counter: Counter = Counter()
    flows_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    extracted_ips: set = set()
    extracted_domains: set = set()
    extracted_urls: set = set()

    normalized_events: List[Dict[str, Any]] = []

    for r in records:
        src = r.get("ip_src")
        dst = r.get("ip_dst")
        port = r.get("dst_port")
        proto = r.get("proto", "IP")
        dns = r.get("dns_query")
        host = r.get("http_host")
        uri = r.get("http_uri")
        epoch = r.get("epoch")

        if src:
            src_ip_counter[src] += 1
            extracted_ips.add(src)
            flows_by_src[src].append(r)
        if dst:
            dst_ip_counter[dst] += 1
            extracted_ips.add(dst)
        if port:
            dst_port_counter[port] += 1
        if dns:
            dns_query_counter[dns] += 1
            extracted_domains.add(dns)
        if host:
            extracted_domains.add(host)
            if uri:
                extracted_urls.add(f"http://{host}{uri}")

        # Normalize timestamp to UTC ISO string
        if epoch:
            try:
                dt = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
                iso_ts = dt.isoformat()
                flow_label = f"{proto} {src or 'N/A'} -> {dst or 'N/A'}"
                if port:
                    flow_label += f":{port}"
                if dns:
                    flow_label += f" (DNS: {dns})"
                elif host:
                    flow_label += f" (HTTP: {host})"

                normalized_events.append(
                    {
                        "timestamp_utc": iso_ts,
                        "src_ip": src,
                        "dst_ip": dst,
                        "raw_line": flow_label,
                    }
                )
            except Exception:
                pass

    # 3. Detection Rules & Findings
    findings: List[Dict[str, Any]] = []
    now_utc = datetime.now(timezone.utc).isoformat()

    # Rule 1: Port Scan Detection (Host hits >= 20 distinct destination ports)
    for host_ip, host_flows in flows_by_src.items():
        distinct_ports = {f["dst_port"] for f in host_flows if f.get("dst_port")}
        if len(distinct_ports) >= 20:
            findings.append(
                {
                    "rule": "PORT_SCAN",
                    "severity": "High",
                    "src_ip": host_ip,
                    "description": f"Host {host_ip} targeted {len(distinct_ports)} distinct ports. Characteristic of an automated reconnaissance port scan.",
                }
            )

    # Rule 2: DNS Spike Detection (Host issues >= 30 DNS requests)
    for dns_domain, query_count in dns_query_counter.items():
        if query_count >= 30:
            findings.append(
                {
                    "rule": "DNS_SPIKE",
                    "severity": "Medium",
                    "src_ip": None,
                    "description": f"High volume query spike ({query_count} queries) observed for domain '{dns_domain}'. Potential C2 beaconing or tunneling.",
                }
            )

    # Rule 3: Rare External IP Connections (Outbound flow to non-private destination)
    external_targets = [dst for dst in dst_ip_counter.keys() if not is_private_ip(dst)]
    for ext_ip in external_targets[:5]:  # Top 5 external targets
        findings.append(
            {
                "rule": "SUSPICIOUS_EXTERNAL_CONNECTION",
                "severity": "Low",
                "src_ip": None,
                "description": f"Outbound flow directed to external IP {ext_ip} ({dst_ip_counter[ext_ip]} flows observed).",
            }
        )

    # 4. Database Sync: events, iocs, findings
    # Clear prior network records for this evidence item to avoid duplication
    execute_db("DELETE FROM events WHERE evidence_id = ? AND source_type = 'pcap'", (evidence_id,))
    execute_db("DELETE FROM iocs WHERE first_evidence_id = ? AND source LIKE '%network%'", (evidence_id,))
    execute_db("DELETE FROM findings WHERE evidence_id = ? AND rule IN ('PORT_SCAN', 'DNS_SPIKE', 'SUSPICIOUS_EXTERNAL_CONNECTION')", (evidence_id,))

    # Insert events (capped at 5,000 for timeline responsiveness)
    for ev_item in normalized_events[:5000]:
        execute_db(
            """
            INSERT INTO events (case_id, evidence_id, timestamp_utc, source_type, src_ip, dst_ip, action, raw_line)
            VALUES (?, ?, ?, 'pcap', ?, ?, 'NETWORK_FLOW', ?)
            """,
            (case_id, evidence_id, ev_item["timestamp_utc"], ev_item["src_ip"], ev_item["dst_ip"], ev_item["raw_line"]),
        )

    # Insert IOCs (strictly adhering to iocs table constraints)
    for ip_val in extracted_ips:
        if ip_val and ip_val not in ("0.0.0.0", "255.255.255.255"):
            execute_db(
                """
                INSERT OR IGNORE INTO iocs (case_id, type, value, first_evidence_id, verdict, source)
                VALUES (?, 'ipv4', ?, ?, 'Unknown', 'network_pcap')
                """,
                (case_id, ip_val, evidence_id),
            )

    for domain_val in extracted_domains:
        if domain_val:
            execute_db(
                """
                INSERT OR IGNORE INTO iocs (case_id, type, value, first_evidence_id, verdict, source)
                VALUES (?, 'domain', ?, ?, 'Unknown', 'network_dns')
                """,
                (case_id, domain_val, evidence_id),
            )

    for url_val in extracted_urls:
        if url_val:
            execute_db(
                """
                INSERT OR IGNORE INTO iocs (case_id, type, value, first_evidence_id, verdict, source)
                VALUES (?, 'url', ?, ?, 'Unknown', 'network_http')
                """,
                (case_id, url_val, evidence_id),
            )

    # Insert findings
    for f in findings:
        execute_db(
            """
            INSERT INTO findings (case_id, evidence_id, rule, severity, src_ip, status, evidence_lines, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, 'Open', ?, ?, ?)
            """,
            (case_id, evidence_id, f["rule"], f["severity"], f.get("src_ip"), f["description"], now_utc, now_utc),
        )

    return {
        "evidence_id": evidence_id,
        "display_name": display_name,
        "packet_count": len(records),
        "tool_used": tool_used,
        "tool_version": tool_version,
        "tshark_available": tshark_active,
        "command": tool_cmd,
        "input_sha256": ev["sha256"],
        "top_src_ips": src_ip_counter.most_common(10),
        "top_dst_ips": dst_ip_counter.most_common(10),
        "top_dns_queries": dns_query_counter.most_common(15),
        "top_dst_ports": dst_port_counter.most_common(10),
        "findings": findings,
        "events_count": len(normalized_events),
        "iocs_count": len(extracted_ips) + len(extracted_domains) + len(extracted_urls),
        "capinfos": cap_info,
    }


def get_stored_network_summary(case_id: int, evidence_id: int) -> Dict[str, Any]:
    """Retrieve existing events, IOCs, and findings for an evidence capture."""
    events = query_db(
        """
        SELECT id, timestamp_utc, src_ip, dst_ip, action, raw_line
        FROM events
        WHERE evidence_id = ? AND source_type = 'pcap'
        ORDER BY timestamp_utc ASC
        LIMIT 50
        """,
        (evidence_id,),
    )
    iocs = query_db(
        """
        SELECT id, type, value, verdict, source
        FROM iocs
        WHERE first_evidence_id = ? AND source LIKE '%network%'
        ORDER BY id ASC
        LIMIT 50
        """,
        (evidence_id,),
    )
    findings = query_db(
        """
        SELECT id, rule, severity, src_ip, status, evidence_lines, first_seen
        FROM findings
        WHERE evidence_id = ? AND rule IN ('PORT_SCAN', 'DNS_SPIKE', 'SUSPICIOUS_EXTERNAL_CONNECTION')
        ORDER BY id DESC
        """,
        (evidence_id,),
    )
    return {
        "events": [dict(e) for e in events],
        "iocs": [dict(i) for i in iocs],
        "findings": [dict(f) for f in findings],
    }
