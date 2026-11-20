# Metadata & EXIF Analysis Module (`app/modules/metadata`)

## Purpose
Reveals hidden digital evidence within file metadata, EXIF/GPS structures, document properties (PDF, Office DOCX), and executable headers (PE). Detects structural file anomalies including JPEG EOF trailing overlay data (steganography), high Shannon entropy (packing/encryption), and file extension discrepancies. Normalizes all extracted timestamps to UTC and inserts synchronized timeline events.

## Path
`app/modules/metadata`

## URL Routes
- `GET /cases/<case_id>/evidence/<evidence_id>/metadata`: View parsed metadata, GPS coordinates, structural findings, and timeline events.
- `POST /cases/<case_id>/evidence/<evidence_id>/metadata/extract`: Trigger on-demand metadata re-extraction and timeline event synchronization.

## DB Tables
- `evidence`: Reads `stored_name`, `sha256`, `display_name`, `mime_real`, `integrity_status`.
- `events`: Inserts normalized metadata timestamps (`source_type='metadata'`, `event_type='FILE_TIMESTAMP'`) for investigation timeline display.
- `findings`: Inserts structural integrity alerts (MIME mismatches, JPEG overlay data, high Shannon entropy, packer signatures).
- `tool_runs` / `custody_log`: Records `ANALYSIS_RUN` when ExifTool is invoked via S6 adapter.

## CIA Controls Implemented
- **Integrity**:
  - Timestamps are normalized to ISO-8601 UTC while preserving original verbatim strings.
  - Analyzed working copies are decrypted in memory or verified before/after execution via S6 containment.
  - All findings and timeline events are explicitly linked to case and evidence IDs.
- **Confidentiality**:
  - GPS coordinates are rendered as formatted decimal/DMS text without external map tile requests (strictly offline, zero external tracking).
  - Case membership enforcement (`@case_member_required`) prevents unauthorized access.
- **Availability**:
  - Primary extraction with ExifTool gracefully falls back to native Python libraries (`Pillow`, `pypdf`, `python-docx`, `pefile`) if external tool is absent.

## How to Test
```bash
pytest tests/test_s7_metadata.py -v
```
