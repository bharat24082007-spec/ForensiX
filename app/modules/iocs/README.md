# S10 — IOC Extractor & Reputation Module

## Overview
The IOC Extractor module automatically identifies and stores Indicators of Compromise (IOCs) found in evidence text content. It operates fully offline — no external reputation lookups are performed by default (`EXTERNAL_LOOKUPS=false`).

## Extracted IOC Types

| Type | Description | Validation |
|------|-------------|-----------|
| `ipv4` | IPv4 addresses | Octets 0–255; private/loopback ranges excluded |
| `domain` | Hostnames | Valid TLD ≥2 chars; .local/.internal excluded |
| `url` | HTTP/HTTPS URLs | Scheme must be http or https |
| `email` | Email addresses | Standard RFC-like format |
| `hash_sha256` | SHA-256 hashes | Exactly 64 hex characters |
| `hash_md5` | MD5 hashes | Exactly 32 hex characters |

## Private/Reserved Ranges Excluded

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8` (loopback)
- `169.254.0.0/16` (link-local)

## Routes

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| GET | `/cases/<id>/iocs` | Member | List all IOCs with optional filters |
| POST | `/cases/<id>/iocs/extract/<ev_id>` | Lead/Analyst | Trigger extraction from evidence |
| GET | `/cases/<id>/iocs/export.csv` | Member | Download IOCs as CSV |

## Defanging Rules

All IOC values are defanged before display:

| Type | Example output |
|------|---------------|
| IPv4 | `1[.]2[.]3[.]4` |
| Domain | `evil[.]com` |
| URL | `hxxp[://]evil[.]com/path` |
| Email | `user@evil[.]com` |
| Hash | (unchanged) |

## Database Table: `iocs`

```sql
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK(type IN ('ipv4', 'domain', 'url', 'email', 'hash_sha256', 'hash_md5')),
    value TEXT NOT NULL,
    first_evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    verdict TEXT NOT NULL DEFAULT 'Unknown',
    source TEXT NOT NULL,
    UNIQUE (case_id, type, value)
);
```

## Security Notes

- All values are **defanged** in templates; never rendered as hyperlinks.
- Parameterized queries only — no string formatting in SQL.
- `EXTERNAL_LOOKUPS=false` by default; reputation checks require explicit opt-in.
- RBAC: Reviewer role cannot trigger extraction (403).
