"""
Tests for Section S8: Network Packet Analysis (Wireshark/TShark Integration & In-Memory Fallback).
Covers:
- RFC-1918 private/public IP classification
- Pure-Python in-memory PCAP dissection
- Detection rules: PORT_SCAN, DNS_SPIKE, SUSPICIOUS_EXTERNAL_CONNECTION
- Database synchronization (events, iocs, findings)
- TShark availability graceful degradation
- Network routes, RBAC access control, and JSON/CSV exports
"""

import io
import socket
import struct
from pathlib import Path
from unittest.mock import patch
from werkzeug.datastructures import FileStorage

import pytest
from app import create_app
from app.db import get_db, init_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.evidence.service import intake_evidence
from app.modules.network.service import (
    is_private_ip,
    parse_pcap_in_memory,
    analyze_network_evidence,
    get_stored_network_summary,
)


def _build_ethernet_ip_tcp_packet(src_ip: str, dst_ip: str, dst_port: int, payload: bytes = b"") -> bytes:
    """Build a raw Ethernet + IPv4 + TCP packet byte buffer."""
    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"
    ihl = 5
    ip_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,
        ip_len,
        1,
        0,
        64,
        6,  # TCP
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        49152,
        dst_port,
        1000,
        0,
        (5 << 4),  # 20 bytes data offset
        0x18,      # PSH, ACK
        8192,
        0,
        0,
    )
    return eth + ip_hdr + tcp_hdr + payload


def _build_ethernet_ip_udp_dns_packet(src_ip: str, dst_ip: str, domain: str) -> bytes:
    """Build a raw Ethernet + IPv4 + UDP packet with DNS query payload."""
    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"

    # Encode domain into DNS wire labels
    labels = b""
    for part in domain.split("."):
        labels += bytes([len(part)]) + part.encode("ascii")
    labels += b"\x00"  # Terminating null
    dns_payload = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)

    udp_len = 8 + len(dns_payload)
    udp_hdr = struct.pack("!HHHH", 53535, 53, udp_len, 0)

    ip_len = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,
        0,
        ip_len,
        2,
        0,
        64,
        17,  # UDP
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return eth + ip_hdr + udp_hdr + dns_payload


def _build_synthetic_pcap(packet_list: list[bytes]) -> bytes:
    """Pack raw packets into standard libpcap format."""
    # 24-byte global header (magic, 2, 4, 0, 0, 65535, 1)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    buf = bytearray(global_hdr)

    base_time = 1700000000
    for idx, pkt in enumerate(packet_list):
        pkt_len = len(pkt)
        pkt_hdr = struct.pack("<IIII", base_time + idx, idx * 1000, pkt_len, pkt_len)
        buf.extend(pkt_hdr)
        buf.extend(pkt)

    return bytes(buf)


@pytest.fixture
def test_env(tmp_path):
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vault"
    db_path = data_dir / "db" / "forensix.db"
    master_key = data_dir / "keys" / "master.key"
    work_dir = data_dir / "work"

    app = create_app({
        "TESTING": True,
        "DATA_DIR": str(data_dir),
        "VAULT_DIR": str(vault_dir),
        "DB_DIR": str(data_dir / "db"),
        "KEYS_DIR": str(data_dir / "keys"),
        "LOGS_DIR": str(data_dir / "logs"),
        "WORK_DIR": str(work_dir),
        "DATABASE_PATH": str(db_path),
        "MASTER_KEY_PATH": str(master_key),
        "WTF_CSRF_ENABLED": False,
        "ALLOW_LAN": False,
        "HOST": "127.0.0.1",
        "PORT": 5000,
        "SECRET_KEY": "test_secret_key_forensix_section8_network",
    })

    with app.app_context():
        init_db(db_path)
        # Create users: name, username, role, password
        lead_id = create_user("Lead User", "lead_user", "Lead", "LeadPass123!")
        analyst_id = create_user("Analyst User", "analyst_user", "Analyst", "AnalystPass123!")
        reviewer_id = create_user("Reviewer User", "reviewer_user", "Reviewer", "ReviewerPass123!")
        outsider_id = create_user("Outsider User", "outsider_user", "Analyst", "OutsiderPass123!")

        # Create case: title, description, priority, lead_user_id
        case_id = create_case("Network Incident Alpha", "Investigating suspicious PCAP captures", "High", lead_id)
        assign_member(case_id, analyst_id, lead_id)
        assign_member(case_id, reviewer_id, lead_id)

    return {
        "app": app,
        "lead_id": lead_id,
        "analyst_id": analyst_id,
        "reviewer_id": reviewer_id,
        "outsider_id": outsider_id,
        "case_id": case_id,
        "vault_dir": vault_dir,
        "work_dir": work_dir,
    }


def test_is_private_ip_classification():
    """Verify accurate classification of RFC-1918 subnets, loopbacks, and public addresses."""
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("10.254.254.254") is True
    assert is_private_ip("172.16.0.5") is True
    assert is_private_ip("172.31.255.255") is True
    assert is_private_ip("192.168.1.100") is True
    assert is_private_ip("127.0.0.1") is True

    # Public IPs
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False
    assert is_private_ip("198.51.100.2") is False
    assert is_private_ip("172.32.0.1") is False


def test_in_memory_pcap_dissector():
    """Verify native PCAP reader extracts IPv4, TCP, UDP, DNS queries and HTTP headers."""
    http_payload = b"GET /admin/login.php HTTP/1.1\r\nHost: portal.internal.corp\r\n\r\n"
    pkt1 = _build_ethernet_ip_tcp_packet("192.168.1.50", "10.0.0.2", 80, http_payload)
    pkt2 = _build_ethernet_ip_udp_dns_packet("192.168.1.50", "1.1.1.1", "c2.malware.com")

    pcap_data = _build_synthetic_pcap([pkt1, pkt2])
    records = parse_pcap_in_memory(pcap_data)

    assert len(records) == 2

    # Verify TCP HTTP record
    rec1 = records[0]
    assert rec1["ip_src"] == "192.168.1.50"
    assert rec1["ip_dst"] == "10.0.0.2"
    assert rec1["dst_port"] == "80"
    assert rec1["proto"] == "TCP"
    assert rec1["http_host"] == "portal.internal.corp"
    assert rec1["http_uri"] == "/admin/login.php"

    # Verify UDP DNS record
    rec2 = records[1]
    assert rec2["ip_src"] == "192.168.1.50"
    assert rec2["ip_dst"] == "1.1.1.1"
    assert rec2["dst_port"] == "53"
    assert rec2["proto"] == "UDP"
    assert rec2["dns_query"] == "c2.malware.com"


def test_threat_detection_port_scan_and_dns_spike(test_env):
    """Verify PORT_SCAN and DNS_SPIKE heuristic detections."""
    app = test_env["app"]
    case_id = test_env["case_id"]
    analyst_id = test_env["analyst_id"]
    vault_dir = test_env["vault_dir"]
    work_dir = test_env["work_dir"]

    # 1. Generate port scan: single host hits 25 distinct ports
    packets = []
    for port in range(100, 125):
        pkt = _build_ethernet_ip_tcp_packet("192.168.1.200", "10.0.0.5", port)
        packets.append(pkt)

    # 2. Generate DNS spike: 35 queries for "tunnel.exfiltration.net"
    for _ in range(35):
        pkt = _build_ethernet_ip_udp_dns_packet("192.168.1.200", "8.8.8.8", "tunnel.exfiltration.net")
        packets.append(pkt)

    pcap_bytes = _build_synthetic_pcap(packets)

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="portscan_and_dns.pcap")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=analyst_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="pcap",
        )

        res = analyze_network_evidence(
            case_id=case_id,
            evidence_id=ev_id,
            acting_user_id=analyst_id,
            vault_dir=vault_dir,
        )

        assert res["packet_count"] == 60
        rules_found = {f["rule"]: f for f in res["findings"]}

        # PORT_SCAN finding
        assert "PORT_SCAN" in rules_found
        assert rules_found["PORT_SCAN"]["severity"] == "High"
        assert rules_found["PORT_SCAN"]["src_ip"] == "192.168.1.200"

        # DNS_SPIKE finding
        assert "DNS_SPIKE" in rules_found
        assert rules_found["DNS_SPIKE"]["severity"] == "Medium"
        assert "tunnel.exfiltration.net" in rules_found["DNS_SPIKE"]["description"]

        # SUSPICIOUS_EXTERNAL_CONNECTION finding (8.8.8.8 is non-private)
        assert "SUSPICIOUS_EXTERNAL_CONNECTION" in rules_found
        assert rules_found["SUSPICIOUS_EXTERNAL_CONNECTION"]["severity"] == "Low"


def test_database_sync_events_and_iocs(test_env):
    """Verify events and iocs tables are populated and queryable."""
    app = test_env["app"]
    case_id = test_env["case_id"]
    lead_id = test_env["lead_id"]
    vault_dir = test_env["vault_dir"]
    work_dir = test_env["work_dir"]

    pkt1 = _build_ethernet_ip_tcp_packet("192.168.1.10", "198.51.100.5", 443)
    pkt2 = _build_ethernet_ip_udp_dns_packet("192.168.1.10", "8.8.8.8", "api.attacker-domain.org")
    pcap_data = _build_synthetic_pcap([pkt1, pkt2])

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(pcap_data), filename="capture.pcap")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=lead_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="pcap",
        )

        analyze_network_evidence(
            case_id=case_id,
            evidence_id=ev_id,
            acting_user_id=lead_id,
            vault_dir=vault_dir,
        )

        # Check events table
        events = query_db("SELECT * FROM events WHERE evidence_id = ? AND source_type = 'pcap'", (ev_id,))
        assert len(events) == 2
        for ev in events:
            assert ev["action"] == "NETWORK_FLOW"
            assert ev["src_ip"] == "192.168.1.10"

        # Check iocs table
        iocs = query_db("SELECT * FROM iocs WHERE first_evidence_id = ?", (ev_id,))
        ioc_types = {ioc["type"] for ioc in iocs}
        assert "ipv4" in ioc_types
        assert "domain" in ioc_types

        ioc_values = {ioc["value"] for ioc in iocs}
        assert "192.168.1.10" in ioc_values
        assert "198.51.100.5" in ioc_values
        assert "api.attacker-domain.org" in ioc_values


def test_graceful_degradation_without_tshark(test_env):
    """Verify that when TShark is missing, the system cleanly degrades to in-memory parsing."""
    app = test_env["app"]
    case_id = test_env["case_id"]
    analyst_id = test_env["analyst_id"]
    vault_dir = test_env["vault_dir"]
    work_dir = test_env["work_dir"]

    pkt = _build_ethernet_ip_tcp_packet("10.0.0.1", "10.0.0.2", 22)
    pcap_bytes = _build_synthetic_pcap([pkt])

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="fallback_test.pcap")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=analyst_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="pcap",
        )

        with patch("app.modules.network.service.is_tool_available", return_value=False):
            res = analyze_network_evidence(
                case_id=case_id,
                evidence_id=ev_id,
                acting_user_id=analyst_id,
                vault_dir=vault_dir,
            )
            assert res["tshark_available"] is False
            assert res["tool_used"] == "ForensiX In-Memory PCAP Engine"
            assert res["packet_count"] == 1


def test_network_routes_rbac_and_exports(test_env):
    """Verify route access control, exports (JSON, CSV), and reviewer restriction."""
    app = test_env["app"]
    case_id = test_env["case_id"]
    analyst_id = test_env["analyst_id"]
    reviewer_id = test_env["reviewer_id"]
    outsider_id = test_env["outsider_id"]
    vault_dir = test_env["vault_dir"]
    work_dir = test_env["work_dir"]

    pkt = _build_ethernet_ip_tcp_packet("192.168.1.1", "10.10.10.10", 80)
    pcap_bytes = _build_synthetic_pcap([pkt])

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="web_traffic.pcap")
        ev_id = intake_evidence(
            case_id=case_id,
            file_storage=storage,
            uploaded_by_user_id=analyst_id,
            vault_dir=vault_dir,
            work_dir=work_dir,
            source_type="pcap",
        )

    client = app.test_client()

    # 1. Unauthenticated -> Redirect to login
    resp = client.get(f"/cases/{case_id}/evidence/{ev_id}/network")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]

    # 2. Outsider (non-case member) -> 404
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/evidence/{ev_id}/network")
    assert resp.status_code == 404

    # 3. Case Member (Analyst) -> 200 OK
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True
    resp = client.get(f"/cases/{case_id}/evidence/{ev_id}/network")
    assert resp.status_code == 200
    assert b"Network Dissection" in resp.data
    assert b"web_traffic.pcap" in resp.data

    # 4. JSON Export -> 200 attachment
    resp_json = client.get(f"/cases/{case_id}/evidence/{ev_id}/network/export.json")
    assert resp_json.status_code == 200
    assert resp_json.mimetype == "application/json"
    assert "attachment; filename=network_analysis_" in resp_json.headers.get("Content-Disposition", "")
    assert b"web_traffic.pcap" in resp_json.data

    # 5. CSV Export -> 200 attachment
    resp_csv = client.get(f"/cases/{case_id}/evidence/{ev_id}/network/export.csv")
    assert resp_csv.status_code == 200
    assert resp_csv.mimetype == "text/csv"
    assert "attachment; filename=network_events_" in resp_csv.headers.get("Content-Disposition", "")
    assert b"Timestamp (UTC),Source IP,Destination IP" in resp_csv.data

    # 6. Reviewer tries POST /analyze -> 403 Forbidden
    with client.session_transaction() as sess:
        sess["_user_id"] = str(reviewer_id)
        sess["_fresh"] = True
    resp_rev = client.post(f"/cases/{case_id}/evidence/{ev_id}/network/analyze", data={"packet_cap": "50000"})
    assert resp_rev.status_code == 403

    # 7. Analyst POST /analyze -> 302 Redirect with success flash
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True
    resp_an = client.post(f"/cases/{case_id}/evidence/{ev_id}/network/analyze", data={"packet_cap": "50000"}, follow_redirects=True)
    assert resp_an.status_code == 200
    assert b"Network analysis complete" in resp_an.data
