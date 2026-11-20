# Network Analysis Module (`app/modules/network`)

## Purpose
Dissects digital network packet captures (PCAP, PCAPNG) to reconstruct communication flows, extract host artifacts, identify top network talkers, and detect anomalous reconnaissance patterns. Automatically populates the case investigation timeline (`events`), IOC catalog (`iocs`), and automated threat findings (`findings`).

## Path
`app/modules/network`

## URL Routes
- `GET /cases/<case_id>/evidence/<evidence_id>/network`: Inspect capture statistics, top talkers, DNS query frequencies, destination ports, threat findings, and recent flows.
- `POST /cases/<case_id>/evidence/<evidence_id>/network/analyze`: Execute on-demand packet dissection with customizable packet caps.
- `GET /cases/<case_id>/evidence/<evidence_id>/network/export.json`: Export structured findings and IOCs as JSON.
- `GET /cases/<case_id>/evidence/<evidence_id>/network/export.csv`: Export extracted packet timeline flows as CSV.

## DB Tables
- `evidence`: Reads file provenance, encrypted payload, and SHA-256 fingerprint.
- `events`: Inserts chronological network flows (`source_type='pcap'`, `action='NETWORK_FLOW'`).
- `iocs`: Inserts extracted IPv4 addresses (`type='ipv4'`), DNS queries (`type='domain'`), and HTTP targets (`type='url'`).
- `findings`: Records heuristic alerts:
  - `PORT_SCAN` (Severity: High): Single source host querying $\ge 20$ destination ports.
  - `DNS_SPIKE` (Severity: Medium): High query frequency ($\ge 30$) for a specific domain.
  - `SUSPICIOUS_EXTERNAL_CONNECTION` (Severity: Low): Outbound flows directed to public non-RFC1918 IPs.
- `tool_runs`: Logs CLI invocation provenance, execution duration, and cryptographic verification when TShark/Capinfos are invoked via S6.

## CIA Controls Implemented
- **Integrity**:
  - Evidence integrity verified against original intake SHA-256 fingerprint prior to dissection.
  - S6 sandboxed ephemeral execution ensures no modification of source evidence.
  - Findings and events are strictly parameterized and linked to evidence and case records.
- **Confidentiality**:
  - All packet dissection runs strictly locally on the loopback-bound host (no DNS lookups, no cloud PCAP analytics, zero external network traffic).
  - Strict RBAC (`@case_member_required`) prevents access by non-members; reviewers are restricted from running active re-dissection.
- **Availability**:
  - Primary dissection via Wireshark CLI (`tshark` and `capinfos`) through S6 subprocess containment engine.
  - Native in-memory fallback PCAP parser guarantees packet dissection, flow reconstruction, and heuristics even if Wireshark is not installed.
  - Configurable packet caps prevent out-of-memory or CPU starvation on massive captures.

## How to Test
```bash
pytest tests/test_s8_network.py -v
```
