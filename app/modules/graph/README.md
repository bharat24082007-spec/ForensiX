# Relationship Graph Module (`app/modules/graph`)

## Purpose
Constructs and visualizes an entity-relationship network graph across case evidence, events, indicators of compromise, and automated findings using NetworkX and a vendored offline vis-network canvas engine.

## Path
`app/modules/graph`

## URL Routes
- `GET /cases/<int:case_id>/graph`: Interactive relationship network visualization page.
- `GET /cases/<int:case_id>/graph/data`: JSON API supplying nodes, edges, degrees, and topological metrics.

## DB Tables
- `events`: Queries connections (`src_ip` -> `dst_ip`) and authentication sessions (`username` -> `src_ip`).
- `iocs`: Queries indicators and linkages to first discovery evidence (`FOUND_IN`).
- `findings`: Queries attacker IPs to highlight suspicious and malicious nodes in red.
- `evidence`: Queries evidence file inventory.

## CIA Controls Implemented
- **Integrity**:
  - Relational graph constructed strictly from immutable records (`events`, `iocs`, `findings`).
  - Topological metrics (density, node degrees) computed mathematically via NetworkX.
- **Confidentiality**:
  - All indicator display labels defanged to prevent accidental link opening.
  - Case membership strictly verified via `@case_member_required`; unauthorized requests receive HTTP 404.
  - Zero external CDN links; uses locally vendored `vis-network.js` canvas engine.

## How to Test
```powershell
python -m pytest tests/test_s14_graph.py -v
```
