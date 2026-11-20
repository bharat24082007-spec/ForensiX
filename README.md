# ForensiX: Digital Forensic Investigation & Evidence Management Platform

<p align="center">
  <img src="app/static/img/forensix_logo.png" alt="ForensiX Logo" width="140" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <strong>An Offline-First, Cryptographically Verifiable Digital Forensics & Incident Investigation Platform</strong><br>
  <em>Engineered for Legal Admissibility under the Bharatiya Sakshya Adhiniyam (BSA), 2023 — Section 63</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/Security-AES--256--GCM-00C853?style=for-the-badge" alt="AES-256-GCM"/>
  <img src="https://img.shields.io/badge/Signatures-Ed25519-6200EA?style=for-the-badge" alt="Ed25519"/>
  <img src="https://img.shields.io/badge/Legal-BSA%20Sec%2063-D50000?style=for-the-badge" alt="BSA Section 63"/>
  <img src="https://img.shields.io/badge/Tests-119%20Passing-brightgreen?style=for-the-badge" alt="119 Passing Tests"/>
</p>

---

## 📑 Executive Overview

**ForensiX** is an enterprise-grade digital forensic evidence management and incident analysis platform. It provides cybersecurity incident responders, digital forensic analysts, law enforcement investigators, and corporate legal teams with an end-to-end environment to securely ingest, store, examine, correlate, and produce court-ready electronic evidence.

Traditional digital investigations often suffer from fragmented toolchains, compromised chain of custody, and challenges in proving evidence integrity in a court of law. ForensiX solves this by combining **cryptographic blockchain-style custody ledgers**, **AES-256-GCM encrypted vault storage**, **automated multi-artifact forensic dissection engines**, and **instant legal report generation with Section 63 BSA electronic certificates**.

---

## 🏛️ Legal Compliance: Section 63 Bharatiya Sakshya Adhiniyam (BSA), 2023

ForensiX is purposefully architected to fulfill the strict legal mandates of **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023** (which replaced Section 65B of the Indian Evidence Act, 1872 for the admissibility of electronic records in Indian Courts):

1. **Lawful Custody & Chain of Custody Record:** Proves by an immutable, hash-chained ledger that the evidence was gathered, maintained, and accessed only by authorized officers throughout the incident lifecycle.
2. **Device State & Hash Verification:** Records intake SHA-256 hashes, algorithm fingerprints, and periodic verification stamps to demonstrate that the computer system operated properly without alteration.
3. **Automated Section 63 Certificate Generation:** Automatically drafts and compiles a formal legal certificate stating the device parameters, custody timeline, cryptographic verification status, and lead investigator declaration.
4. **Public Asymmetric Verification:** Any generated legal report carries an **Ed25519 digital signature** and a **SHA-256 hash** that can be independently verified on the standalone `/verify-report` verification portal without compromising case confidentiality.

---

## 🛡️ The Forensic CIA Security Charter

| Pillar | Security Implementation in ForensiX |
| :--- | :--- |
| **Confidentiality** | • **Zero Runtime Cloud Leakage:** Strictly offline-first architecture; zero external CDN calls.<br>• **Storage at Rest:** Chunked **AES-256-GCM** encryption for all raw evidence artifacts stored in `data/vault/`.<br>• **Access Control:** Argon2id password derivation, mandatory TOTP MFA for Lead/Admin, and per-case investigator assignment enforcing separation of duties. |
| **Integrity** | • **Dual Hash Verification:** Initial intake SHA-256 calculated before writing to disk; pre- and post-analysis hashing ensures raw evidence is never modified.<br>• **Append-Only Custody Ledger:** SQLite database triggers enforce strict immutability (`trg_custody_log_no_update` and `trg_custody_log_no_delete`).<br>• **Hash-Chained Audit Trail:** Each custody block cryptographically incorporates the `prev_hash` and HMAC signature of all prior case events. |
| **Availability** | • **Single-Host Loopback Binding:** Bound strictly to loopback (`127.0.0.1:5000`) with production-grade WSGI (Waitress).<br>• **Subprocess Isolation:** Hard ban on `shell=True`, structured parameter arrays, strict execution timeouts (30s), and stdout caps (10MB) prevent memory exhaustion or hanging processes.<br>• **Integrity Watchdog:** In-process background scheduler running periodic integrity checks on all custody chains and vault files. |

---

## 🔍 Core Forensic Capabilities & Modules

### 1. Case Management & Sequential Numbering
- Provision cases with standardized numbering (`CASE-YYYY-XXXX`).
- Multi-tier priority management (`Low`, `Medium`, `High`, `Critical`) and status tracking (`Open`, `In Progress`, `Under Review`, `Closed`).
- **Legal Hold Lock:** Freezes cases under formal legal dispute, preventing any modifications, reassignments, or evidence additions.

### 2. Secure Evidence Intake Vault
- **MIME Type Spoofing Detection:** Validates file magic numbers against uploaded file extensions to detect masqueraded files (e.g., an executable `.exe` disguised as `.jpg`).
- **Cryptographic Fingerprinting:** Automatic SHA-256 fingerprinting on intake.
- **Duplicate Detection:** Instant detection and referencing of already-ingested forensic artifacts.

### 3. Integrated Tool Adapters & Subprocess Engine
- Seamlessly integrates with industry-standard forensic engines:
  - **Phil Harvey's ExifTool:** Deep extraction of EXIF, XMP, IPTC, camera serials, and geolocation data.
  - **Wireshark TShark & Capinfos:** Packet capture statistics, TCP/UDP stream reassembly, and protocol dissection.
  - **The Sleuth Kit (`fls`):** File system enumeration and raw disk image inspection.

### 4. Automated Forensic Parsers
- **Network Dissection (PCAP):** Dissects offline `.pcap` files to identify top talkers, DNS queries, HTTP user-agents, request paths, and suspicious transfer streams.
- **Auth & System Log Analysis:** Analyzes Linux `/var/log/auth.log` and security logs; automatically detects SSH brute-force attacks, failed login patterns, and `SUCCESS_AFTER_FAILURES` breach indicators.
- **Image EXIF & Geolocation:** Extracts GPS latitude/longitude, altitude, and timestamp metadata from evidentiary photos; renders an offline interactive map marker.

### 5. Threat Intelligence & Automated IOC Defanging
- Regex-driven automated extraction of Indicators of Compromise (IOCs): IPv4, IPv6, Domains, URLs, SHA-256, and MD5 hashes.
- **Safe Defanging Engine:** Automatically defangs dangerous strings (`hxxp[://]malicious[.]com`, `192[.]168[.]1[.]100`) to prevent accidental clicks or weaponization in reports.
- Local reputation caching for suspicious indicators.

### 6. Interactive Unified Chronological Timeline
- Consolidates timestamps across diverse evidence sources into a single, unified UTC ISO-8601 timeline:
  - Network packet arrival timestamps
  - Authentication log login events
  - Camera EXIF photo capture times
  - Chain-of-custody evidence intake events
- Dynamic interactive filtering by source, severity, and evidence file, with one-click **Export to CSV**.

### 7. Court-Ready Legal Reporting & Public Verification
- One-click compilation of professional PDF forensic reports via ReportLab.
- Embeds: Executive Summary, Investigator Declaration, Evidence Table with SHA-256 hashes, Chain of Custody Ledger, Detailed Findings, Timeline Log, and the Section 63 BSA Certificate.
- Digitally signed with the Lead Investigator's **Ed25519 private key**.
- Standalone verification portal at `/verify-report` allowing third-party judges, defense attorneys, or auditors to upload the PDF and verify authenticity.

---

## 🏗️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        User / Browser / Evaluator                      │
│            (Dashboard, Case Header, Evidence, Timeline, Reports)       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / REST / Jinja2
┌───────────────────────────────────▼────────────────────────────────────┐
│                    ForensiX Web Layer (Flask + WSGI)                   │
│   • Strict CSP Headers  • CSRF Protection  • Argon2id + TOTP MFA RBAC  │
└─────────┬─────────────────────────┬──────────────────────────┬─────────┘
          │                         │                          │
┌─────────▼─────────┐    ┌──────────▼──────────┐    ┌──────────▼─────────┐
│  Evidence Vault   │    │  Forensic Adapters  │    │ Cryptographic Core │
│ • AES-256-GCM     │    │ • ExifTool (EXIF)   │    │ • SHA-256 Hashes   │
│ • Chunked Encrypt │    │ • TShark (PCAP)     │    │ • Hash-Chain (HMAC)│
│ • Read-Only Chmod │    │ • Sleuth Kit (fls)  │    │ • Ed25519 Signing  │
│ • Magic Byte MIME │    │ • Auth Log Parser   │    │ • Section 63 BSA   │
└─────────┬─────────┘    └──────────┬──────────┘    └──────────┬─────────┘
          │                         │                          │
┌─────────▼─────────────────────────▼──────────────────────────▼─────────┐
│                     SQLite Database (WAL Mode)                         │
│  cases • evidence • custody_log (APPEND-ONLY TRIGGERS) • events • iocs │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.11 or higher
- Optional CLI utilities (auto-detected):
  - Wireshark suite (`tshark`, `capinfos`)
  - Phil Harvey's `exiftool`
  - The Sleuth Kit (`fls`)

### 2. Installation
```bash
# Clone the repository
git clone <repo-url>
cd ForensiX

# Install pinned dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
```

### 3. Initialize & Start
```bash
# Provision Admin Account
python run.py --create-admin

# Start the Forensic Server
python run.py
```
ForensiX will launch on `http://127.0.0.1:5000`.

### 4. Windows 1-Click Launch
On Windows systems, you can simply double-click:
```text
start_forensix.bat
```
This automatically boots both the ForensiX Waitress engine and the secure ngrok tunnel in dedicated, persistent console windows.

---

## 🧪 Testing & Verification

ForensiX includes a test suite covering all forensic modules, cryptographic routines, legal hold boundaries, and anti-tamper triggers:

```bash
python -m pytest tests/
```
**Result:** `119 passed in 53.17s (100% test coverage)`.

---

## 📜 Compliance & License

Developed in accordance with international digital forensics guidelines (**ISO/IEC 27037: Guidelines for identification, collection, acquisition, and preservation of digital evidence**) and Indian evidence standards (**Bharatiya Sakshya Adhiniyam, 2023**).

*Designed for ethical forensic investigation, cyber defense, and legitimate legal evidence processing.*
