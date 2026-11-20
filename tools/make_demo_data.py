"""
ForensiX Forensic Demo Data Generator.
Generates realistic, offline-safe digital evidence artifacts for demonstrations,
presentations, training, and integration testing.

Generated Artifacts:
  1. auth.log            - Linux SSH auth log with 150 failed attempts + success (SUCCESS_AFTER_FAILURES finding)
  2. sample_photo.jpg    - Valid JPEG image with EXIF camera and GPS coordinates (New Delhi, India)
  3. fake_photo.jpg      - Executable header (MZ) disguised with .jpg extension for mismatch detection
  4. eicar.com           - Standard anti-virus test file string
  5. suspicious_notes.txt- Incident text notes with IPs, URLs, domains, and MD5/SHA256 hashes
  6. sample.pcap         - Synthetic valid libpcap file containing TCP HTTP requests and UDP DNS queries
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import struct
import sys
from typing import Dict, List, Optional

try:
    from PIL import Image
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False


EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def generate_demo_auth_log(dest_path: Path) -> Path:
    """Generate auth.log with normal logins, 150 failed SSH attempts from one IP, then 1 success."""
    lines: List[str] = [
        "Jan 15 10:00:01 forensic-srv systemd[1]: Started Session 1 of user root.",
        "Jan 15 10:01:14 forensic-srv sshd[1200]: Accepted publickey for analyst from 192.168.1.50 port 54321 ssh2: RSA SHA256:abc12345",
        "Jan 15 10:01:15 forensic-srv sshd[1200]: pam_unix(sshd:session): session opened for user analyst by (uid=0)",
        "Jan 15 10:05:22 forensic-srv sshd[1205]: Accepted password for admin from 192.168.1.51 port 54322 ssh2",
        "Jan 15 10:08:40 forensic-srv sudo[1210]: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/ls -la",
    ]

    attacker_ip = "198.51.100.77"
    # Generate 150 failed attempts from attacker_ip
    for i in range(1, 151):
        minute = (i // 15) + 10
        second = (i * 3) % 60
        pid = 2000 + i
        port = 40000 + i
        lines.append(
            f"Jan 15 10:{minute:02d}:{second:02d} forensic-srv sshd[{pid}]: Failed password for invalid user root from {attacker_ip} port {port} ssh2"
        )

    # Followed immediately by a successful login from the same attacker IP
    lines.extend([
        f"Jan 15 10:21:05 forensic-srv sshd[2155]: Accepted password for root from {attacker_ip} port 40155 ssh2",
        f"Jan 15 10:21:06 forensic-srv sshd[2155]: pam_unix(sshd:session): session opened for user root by (uid=0)",
        "Jan 15 10:22:18 forensic-srv sudo[2160]: root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash -i",
    ])

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest_path


def generate_demo_image(dest_path: Path) -> Path:
    """Generate a valid JPEG with EXIF tags (Nikon D850, DateTime, and GPS coordinates)."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if not HAS_PILLOW:
        # Fallback: write minimal JFIF header
        jfif = (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
            b"\xff\xdb\x00C\x00" + (b"\x08" * 64) +
            b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
            b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9"
        )
        dest_path.write_bytes(jfif)
        return dest_path

    # Create 200x200 sample image
    img = Image.new("RGB", (200, 200), color=(52, 101, 164))
    exif = img.getexif()

    # Standard EXIF tags
    exif[0x010F] = "Nikon"                           # Make
    exif[0x0110] = "D850"                            # Model
    exif[0x0131] = "ForensiX Platform v2.0"          # Software
    exif[0x0132] = "2026:01:15 14:30:00"            # DateTime

    # GPS IFD tags (0x8825): Coordinates for New Delhi (28°36'50.4" N, 77°12'32.1" E)
    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[1] = "N"                                 # GPSLatitudeRef
    gps_ifd[2] = (28.0, 36.0, 50.4)                 # GPSLatitude (deg, min, sec)
    gps_ifd[3] = "E"                                 # GPSLongitudeRef
    gps_ifd[4] = (77.0, 12.0, 32.1)                 # GPSLongitude (deg, min, sec)
    gps_ifd[7] = (14.0, 30.0, 0.0)                  # GPSTimeStamp

    img.save(str(dest_path), format="JPEG", exif=exif)
    return dest_path


def generate_demo_fake_photo(dest_path: Path) -> Path:
    """Generate fake photo.jpg that starts with executable DOS/PE MZ header for mismatch detection."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    # DOS stub header
    mz_payload = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00"
        b"This program cannot be run in DOS mode.\r\r\n$"
        b"\x00" * 32
    )
    dest_path.write_bytes(mz_payload)
    return dest_path


def generate_demo_eicar(dest_path: Path) -> Path:
    """Generate standard EICAR anti-virus test file (safely handles host AV quarantine)."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest_path.write_bytes(EICAR_STRING)
    except PermissionError:
        # Windows Defender or host real-time protection actively locks or quarantines raw EICAR string
        pass
    return dest_path


def generate_demo_notes(dest_path: Path) -> Path:
    """Generate suspicious notes text file with IP, URLs, domains, and cryptographic hashes."""
    notes = """Incident Investigation Field Notes - Case #2026-FX01
------------------------------------------------------
Timestamp of Observation: 2026-01-15 10:25:00 UTC
Investigating Officer: Lead Forensic Examiner

Identified Threat Infrastructure:
1. Primary Ingress IP: 198.51.100.77 (Observed in brute-force SSH logs)
2. Exfiltration Dropzone IP: 203.0.113.195
3. Malicious Command & Control Domain: c2-update-service.darknet-relay.org
4. Compromised Internal Relay: 10.0.0.14
5. Staging Dropper URL: http://phish-secure-portal.info/payloads/dropper.bin
6. Secondary Exfil URL: https://data-storage-box.biz/upload?ref=2026

Cryptographic Indicators:
- Backdoor Binary SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- Stager DLL MD5: c4ca4238a0b923820dcc509a6f75849b
- Contact Email: adversary@shadow-ops.org

Initial Assessment:
Suspicious SSH activity detected against edge server; payload exfiltration suspected via HTTP POST.
"""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(notes, encoding="utf-8")
    return dest_path


def _build_ethernet_ip_tcp_packet(src_ip: str, dst_ip: str, dst_port: int, payload: bytes = b"") -> bytes:
    """Construct raw Ethernet + IPv4 + TCP packet bytes."""
    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"
    ihl = 5
    ip_len = 20 + 20 + len(payload)
    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,
        ip_len,
        54321,
        0,
        64,
        6,  # TCP
        0,  # Checksum
        src_bytes,
        dst_bytes,
    )

    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        49152,
        dst_port,
        1000,
        0,
        (5 << 4),
        0x02,  # SYN flag
        65535,
        0,
        0,
    )

    return eth + ip_hdr + tcp_hdr + payload


def _build_ethernet_ip_udp_dns_packet(src_ip: str, dst_ip: str, query_domain: str) -> bytes:
    """Construct raw Ethernet + IPv4 + UDP + DNS query packet bytes."""
    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"
    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))

    # DNS Question Section
    qname = b""
    for part in query_domain.split("."):
        qname += bytes([len(part)]) + part.encode("ascii")
    qname += b"\x00"
    dns_payload = (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", 1, 1)  # Type A, Class IN
    )

    udp_len = 8 + len(dns_payload)
    udp_hdr = struct.pack("!HHHH", 53535, 53, udp_len, 0)

    ip_len = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,
        0,
        ip_len,
        12345,
        0,
        64,
        17,  # UDP
        0,
        src_bytes,
        dst_bytes,
    )

    return eth + ip_hdr + udp_hdr + dns_payload


def generate_demo_pcap(dest_path: Path) -> Path:
    """Generate a synthetic, valid PCAP capture file."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    http_get = b"GET /admin/dashboard HTTP/1.1\r\nHost: internal-portal.corp\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    pkt1 = _build_ethernet_ip_tcp_packet("192.168.1.50", "10.0.0.1", 80, http_get)
    pkt2 = _build_ethernet_ip_udp_dns_packet("192.168.1.50", "8.8.8.8", "c2-update-service.darknet-relay.org")
    pkt3 = _build_ethernet_ip_tcp_packet("192.168.1.50", "198.51.100.77", 443)

    packets = [pkt1, pkt2, pkt3]

    # Standard libpcap global header: magic, major, minor, thiszone, sigfigs, snaplen, network (Ethernet=1)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    buf = bytearray(global_hdr)

    base_time = 1700000000
    for idx, pkt in enumerate(packets):
        pkt_len = len(pkt)
        pkt_hdr = struct.pack("<IIII", base_time + idx, idx * 1000, pkt_len, pkt_len)
        buf.extend(pkt_hdr)
        buf.extend(pkt)

    dest_path.write_bytes(bytes(buf))
    return dest_path


def generate_all_demo_data(target_dir: Optional[Path] = None) -> Dict[str, Path]:
    """Generate all demo evidence files in the specified directory."""
    if target_dir is None:
        target_dir = Path(__file__).resolve().parent / "demo"

    target_dir.mkdir(parents=True, exist_ok=True)

    results: Dict[str, Path] = {
        "auth_log": generate_demo_auth_log(target_dir / "auth.log"),
        "sample_photo": generate_demo_image(target_dir / "sample_photo.jpg"),
        "fake_photo": generate_demo_fake_photo(target_dir / "fake_photo.jpg"),
        "eicar": generate_demo_eicar(target_dir / "eicar.com"),
        "notes": generate_demo_notes(target_dir / "suspicious_notes.txt"),
        "pcap": generate_demo_pcap(target_dir / "sample.pcap"),
    }
    return results


def main() -> int:
    """CLI entry point for demo data generation."""
    parser = argparse.ArgumentParser(description="ForensiX Forensic Demo Data Generator")
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="",
        help="Target directory for generated demo files (default: tools/demo/)",
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir) if args.output_dir else Path(__file__).resolve().parent / "demo"
    print(f"[*] Generating ForensiX demo data in: {out_dir}")

    files = generate_all_demo_data(out_dir)

    print("\n[+] Successfully generated all forensic demo artifacts:")
    for key, path in files.items():
        if path.exists():
            sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
            size_bytes = path.stat().st_size
            print(f"  - {path.name:<22} ({size_bytes:>6} bytes)  SHA-256: {sha256}")
        else:
            print(f"  - {path.name:<22} (quarantined/removed by host AV in real-time as expected)")

    print("\n[✓] Demo data is ready. Refer to docs/DEMO_SCRIPT.md for demonstration steps.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
