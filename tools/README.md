# ForensiX Tools & Demo Data Generator (`tools/`)

## 1. Purpose
The `tools/` package provides offline utility scripts for generating synthetic, realistic digital forensic artifacts used in system verification, live demonstrations, student labs, and automated end-to-end testing.

## 2. Path
`tools/`
- `make_demo_data.py`: CLI generator script for demo evidence files.
- `demo/`: Storage directory for generated demonstration artifacts.

## 3. URL Routes
*None* (Standalone CLI utility invoked via terminal or testing suite).

## 4. DB Tables
Does not directly interact with database tables; files generated here are ingested into `evidence`, `custody_log`, `events`, `iocs`, `findings`, and `timeline_events` through standard intake workflows.

## 5. Generated Demo Artifacts
| Filename | Type | Purpose / Triggered Findings |
|---|---|---|
| `auth.log` | Linux SSH Log | 150 failed SSH logins from `198.51.100.77` followed by a successful login. Triggers `BRUTE_FORCE`, `SUCCESS_AFTER_FAILURES` (Critical), and populates IOCs and timeline. |
| `sample_photo.jpg` | JPEG Image | Valid image with EXIF metadata (Make: Nikon, Model: D850, Timestamp: 2026:01:15 14:30:00) and GPS location (28°36'50.4" N, 77°12'32.1" E - New Delhi, India). |
| `fake_photo.jpg` | PE Executable | Starts with DOS `MZ` executable header despite `.jpg` extension, demonstrating file signature / MIME mismatch detection. |
| `eicar.com` | Anti-Virus Test String | Standard 68-byte EICAR antivirus test file (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`). |
| `suspicious_notes.txt` | Text Document | Investigative notes containing defangable IOCs: IPv4 (`198.51.100.77`, `203.0.113.195`), domains (`c2-update-service.darknet-relay.org`), URLs, MD5 and SHA-256 hashes. |
| `sample.pcap` | Network Capture | Valid libpcap file containing IPv4 TCP HTTP GET request, UDP DNS query, and TLS SYN packet. Dissected via TShark or native in-memory engine. |

## 6. CIA Controls
- **Confidentiality**: Synthetically generated data; contains zero real personally identifiable information (PII), proprietary source code, or live exploits.
- **Integrity**: Produces deterministic, byte-accurate cryptographic hashes for verification against custody chains.
- **Availability**: Generates fully offline artifacts without requiring Internet connectivity, external package downloads, or cloud API calls.

## 7. How to Run & Test
```bash
# Generate demo files into tools/demo/
python tools/make_demo_data.py

# Specify custom output directory
python tools/make_demo_data.py --output-dir custom/folder/

# Run automated tests
pytest tests/test_s15_demo.py
```
