# S11 — Investigation Timeline Module

## Overview
The Timeline module merges events from multiple forensic data sources into a
unified chronological view. It supports both an interactive vis-timeline widget
and a sortable table view, with full filter support and CSV export.

## Data Sources

| Source | Table | Notes |
|--------|-------|-------|
| `auth.log` | `events` | SSH authentication events from log analyser |
| `web.log` | `events` | HTTP access log events |
| `pcap` | `events` | Network packet events from tshark adapter |
| `metadata` | `events` | File metadata events from exiftool adapter |
| `custody` | `custody_log` | Chain-of-custody audit events |

## Routes

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| GET | `/cases/<id>/timeline` | Member | Interactive timeline page |
| GET | `/cases/<id>/timeline/data` | Member | JSON endpoint for vis-timeline |
| GET | `/cases/<id>/timeline/export.csv` | Member | CSV download (logged) |

## Filter Parameters (query string)

| Param | Values | Description |
|-------|--------|-------------|
| `source` | auth.log, web.log, pcap, metadata, custody | Filter by source type |
| `evidence_id` | integer | Filter to a specific evidence item |
| `severity` | Info, Low, Medium, High, Critical | Filter by severity |
| `start_date` | ISO-8601 string | Events at or after this timestamp |
| `end_date` | ISO-8601 string | Events at or before this timestamp |

## Severity Derivation

Severity is **not** stored on the events table directly. Instead:

1. All findings for the case are queried (`findings.evidence_lines` contains comma-separated line numbers).
2. If an event's `line_no` matches a finding for the same `evidence_id`, the finding's severity is applied.
3. Otherwise the event is marked `Info`.
4. When multiple findings match, the highest severity wins.

## Export Custody Logging

Every CSV export is recorded in the custody chain:

```python
custody_append(case_id, None, user_id, "EXPORT_TIMELINE_CSV", {"filters": {...}})
```

## vis-timeline Stub

`app/static/vendor/vis-timeline/vis-timeline.js` provides a minimal stub that
defines the `vis` namespace so the page does not crash in offline environments.

> **Replace** with the vendored library from https://unpkg.com/vis-timeline@latest
> before deploying to a production or demo environment.

## All Times UTC

All timestamps stored in `events.timestamp_utc` and `custody_log.timestamp_utc`
are in UTC. The timeline view displays a prominent "All times UTC" label.
