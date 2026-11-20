# ForensiX External Tool Adapters (`app/adapters/`)

## 1. Purpose
Provides a unified containment engine and standardized interface adapters for external forensic command-line tools (Wireshark TShark, Capinfos, ExifTool, The Sleuth Kit `fls`). Enforces strict execution safety: non-root isolated processes, zero `shell=True`, parameter arrays, output byte caps, execution timeouts, work directory wiping, and pre/post SHA-256 integrity verification.

## 2. Path
`app/adapters/`
- `base.py`: Low-level subprocess runner, timeout monitor, and SHA-256 working copy validator.
- `registry.py`: Dynamic tool availability detector and system PATH locator.
- `tshark.py`: Wireshark packet dissection and capinfos statistical summaries.
- `exiftool.py`: Phil Harvey's ExifTool metadata and tag extraction adapter.
- `sleuthkit.py`: The Sleuth Kit `fls` file system and directory lister for disk images.

## 3. URL Routes
- Handled through parent module routes (`/cases/<id>/evidence/...` and `/system/tools`).

## 4. DB Tables
- `custody_log`: Records tool name, binary path, version, and input SHA-256 hash before and after execution.
- `jobs`: Asynchronous background task status tracking.

## 5. CIA Controls
- **Confidentiality**: Isolated execution in temporary `data/work/` subdirectories with secure cleanup and zero external telemetry.
- **Integrity**: Working copies are hashed before and after execution. Original evidence in `data/vault/` is never touched.
- **Availability**: Hard timeouts (e.g., 30s) and stdout/stderr output caps prevent runaway child processes or denial-of-service hangs. App degrades gracefully if a binary is not found.

## 6. How to Test
```bash
pytest tests/test_s6_adapters.py tests/test_s15_demo.py
```
