# ForensiX Live Demonstration & Evaluation Script

**Duration:** 3 to 4 minutes  
**Target Audience:** Forensic Examiners, Academic Evaluators, Judicial Reviewers  
**Environment:** Offline, Single-Host (`127.0.0.1:5000`)

---

## Pre-Demo Quick Setup (30 Seconds)

Before starting the presentation, ensure the server is running and demo artifacts are generated:

```bash
# 1. Generate the demo evidence artifacts
python tools/make_demo_data.py

# 2. Start the ForensiX single-host server
python run.py
```

Open your browser to: **`http://127.0.0.1:5000`**

---

## Scene 1: Confidentiality & Chain of Custody Intake (0:00 – 0:45)
**Key Message:** *ForensiX enforces strict role-based access, MFA, and immediate cryptographic anchoring upon evidence intake.*

1. **Login with MFA:**
   - Navigate to `/login`.
   - Sign in as Lead Investigator:
     - Username: `lead1`
     - Password: `Password123!`
   - Enter your configured TOTP token (or use initial setup QR code).
2. **Create an Investigation Case:**
   - Click **+ New Case**.
   - Title: `Operation Red Sandstorm`
   - Description: `Investigating unauthorized SSH intrusions and data exfiltration.`
   - Priority: `High` -> Click **Create Case**.
3. **Upload Digital Evidence:**
   - Inside the case, open the **Evidence** tab and click **+ Add Evidence**.
   - File: Select `tools/demo/sample_photo.jpg` (or drag & drop).
   - Source Type: `Image`
   - Description: `Suspect camera image recovered from endpoint.`
   - Click **Upload Evidence**.
4. **Point Out Integrity Anchors:**
   - Point out the calculated **SHA-256** hash displayed immediately in the evidence table.
   - Mention: *The file was chunked, encrypted at rest using AES-256-GCM, and stored with a UUID name in the vault (`data/vault/`). The master key is stored separately in `data/keys/`.*

---

## Scene 2: Cryptographic Custody Chain Verification (0:45 – 1:15)
**Key Message:** *Every event forms an immutable, cryptographically linked hash chain.*

1. **View Custody Log:**
   - Click the **Custody** tab.
   - Show the initial intake entry: Entry #1, Action: `INTAKE`, with `previous_hash` (`0000...0000`) and the calculated `entry_hash`.
2. **Click "Verify Custody Chain":**
   - Click the **Verify Chain** button.
   - **Result:** A prominent **GREEN** banner appears:
     > `✓ Custody Chain Intact: All entries cryptographically verified.`
   - Explain: *Every custody record hashes the previous entry's hash, timestamp, actor, action, and target hash. SQL triggers prevent any `UPDATE` or `DELETE` on this table.*

---

## Scene 3: Anti-Tamper Demonstration (Broken Chain Detection) (1:15 – 1:50)
**Key Message:** *Even a rogue DBA cannot alter custody records without immediate mathematical detection.*

1. **Attempt Direct SQLite Modification:**
   - Open a separate terminal and demonstrate trigger protection:
     ```bash
     python -c "
     import sqlite3
     conn = sqlite3.connect('data/db/forensix.db')
     try:
         conn.execute('UPDATE custody_log SET action = \"TAMPERED\" WHERE id = 1')
         conn.commit()
     except Exception as e:
         print('[BLOCKED BY TRIGGER]:', e)
     "
     ```
   - Show the console output: `[BLOCKED BY TRIGGER]: sqlite3.IntegrityError: Custody log is append-only`.
2. **Simulate Out-of-Band Database Tampering (Drop Trigger, Mutate, Re-add Trigger):**
   - Run the provided simulation script:
     ```bash
     python -c "
     import sqlite3
     conn = sqlite3.connect('data/db/forensix.db')
     conn.execute('DROP TRIGGER IF EXISTS trg_custody_log_no_update')
     conn.execute('UPDATE custody_log SET detail_json = \"{\\\"tampered\\\": true}\" WHERE id = 1')
     conn.commit()
     print('[!] Record #1 tampered successfully')
     "
     ```
3. **Verify Chain in Web UI:**
   - Return to the browser and click **Verify Chain** again.
   - **Result:** A prominent **RED** alert banner appears:
     > `✕ Custody Chain Broken at Entry #1: Hash mismatch detected. System Integrity Compromised.`
   - Point out: *The platform accurately pinpoints the exact entry where the link was broken.*
4. **Restore Clean State for Demo Continuity:**
   ```bash
   python -c "
   import sqlite3
   conn = sqlite3.connect('data/db/forensix.db')
   with open('app/schema.sql', 'r', encoding='utf-8') as f:
       schema = f.read()
   trg_idx = schema.find('CREATE TRIGGER IF NOT EXISTS trg_custody_log_no_update')
   trg_sql = schema[trg_idx:schema.find('END;', trg_idx)+4]
   conn.execute('DROP TRIGGER IF EXISTS trg_custody_log_no_update')
   conn.execute('UPDATE custody_log SET detail_json = \"{\\\"intake\\\": true}\" WHERE id = 1')
   conn.commit()
   conn.executescript(trg_sql)
   print('[✓] Restored and re-secured')
   "
   ```
       schema = f.read()
   trg_idx = schema.find('CREATE TRIGGER trg_custody_no_update')
   trg_sql = schema[trg_idx:schema.find('END;', trg_idx)+4]
   conn.executescript(trg_sql)
   print('[✓] Restored and re-secured')
   "
   ```

---

## Scene 4: Physical Vault Watchdog & Silent Tamper Detection (1:50 – 2:20)
**Key Message:** *If raw encrypted vault files on disk are corrupted or swapped, the background watchdog flags them as COMPROMISED.*

1. **Simulate Vault Bit-Flip:**
   - Corrupt one byte of an encrypted vault file:
     ```bash
     python -c "
     import os, glob
     files = glob.glob('data/vault/*.enc')
     if files:
         target = files[0]
         # Remove read-only attribute temporarily
         import stat
         os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
         with open(target, 'r+b') as f:
             f.seek(16)
             b = f.read(1)
             f.seek(16)
             f.write(bytes([b[0] ^ 0xFF]))
         os.chmod(target, stat.S_IREAD)
         print(f'[!] Tampered 1 byte in {target}')
     "
     ```
2. **Trigger Watchdog Integrity Scan:**
   - In the browser, navigate to the **Custody** or **Integrity** page and click **Run Integrity Audit** (or trigger `/cases/<id>/integrity/run`).
   - Observe that the evidence badge status changes to **COMPROMISED**.
   - Point out: *ForensiX never serves tampered evidence to investigators or forensic tools.*

---

## Scene 5: Automated Log Analysis & Threat Detection (2:20 – 2:50)
**Key Message:** *ForensiX parses raw logs into exact line-indexed events, extracts IOCs, and flags high-severity intrusions.*

1. **Upload `auth.log`:**
   - Click **Evidence** -> **+ Add Evidence**.
   - Select `tools/demo/auth.log` -> Click **Upload**.
2. **Execute Log Analyzer:**
   - Click on the uploaded `auth.log` item -> Click **Analyze Log**.
3. **Show Detections:**
   - **Critical Finding:** `SUCCESS_AFTER_FAILURES`
     - Displays: *150 failed attempts from IP `198.51.100.77` followed by successful authentication for `root`.*
   - **High Finding:** `BRUTE_FORCE` pattern detected.
4. **Inspect Unified Timeline & IOCs:**
   - Switch to the **Timeline** tab: show how log events and intake events are chronologically sorted in UTC.
   - Switch to the **IOCs** tab: show `198.51.100.77` automatically extracted and defanged (`198[.]51[.]100[.]77`).

---

## Scene 6: Forensic Report Generation & Section 63 BSA Certificate (2:50 – 3:30)
**Key Message:** *Automatic compliance with Indian Law: Bharatiya Sakshya Adhiniyam (BSA), 2023, Section 63 electronic record certification.*

1. **Draft and Sign Report:**
   - Open the **Reports** tab.
   - Click **+ Generate Report**.
   - Title: `Forensic Examination Report - Case FX01`
   - Executive Summary: `Intrusion analysis confirming credential brute-forcing and successful privilege acquisition.`
   - Click **Generate PDF Report**.
2. **Digitally Sign Report:**
   - Click **Sign Report** (using examiner's Ed25519 cryptographic key).
   - Show the generated **Section 63 BSA Electronic Certificate**:
     - Details device specification, SHA-256 master hash, chain head hash, and signing timestamp.
3. **Verify Report Authenticity:**
   - Download the signed PDF (`report_case_1.pdf`).
   - Click **Verify Report** in the top navigation or visit `/verify-report`.
   - Upload the downloaded PDF.
   - **Result:** **GREEN** confirmation:
     > `✓ Cryptographically Valid Report: Signed by Lead Examiner (lead1). Hash matches internal record.`

---

## Scene 7: Report Tamper Rejection (3:30 – 4:00)
**Key Message:** *Any alteration of an exported court document invalidates its legal admissibility.*

1. **Mutate 1 Byte of the Exported PDF:**
   - Run in the terminal:
     ```bash
     python -c "
     import glob
     pdfs = glob.glob('data/reports/*.pdf')
     if pdfs:
         target = pdfs[0]
         data = bytearray(open(target, 'rb').read())
         data[-10] ^= 0x55
         with open('tampered_report.pdf', 'wb') as f:
             f.write(data)
         print('[!] Created tampered_report.pdf')
     "
     ```
2. **Re-upload to `/verify-report`:**
   - In the browser, upload `tampered_report.pdf` to `/verify-report`.
   - **Result:** **RED** rejection banner:
     > `✕ Invalid Report: Signature or hash mismatch. Document has been modified or corrupted.`
3. **Wrap-up Conclusion:**
   - *"ForensiX provides end-to-end mathematical trust for digital evidence: from intake, through analysis, to court presentation."*

---

## Summary Matrix of Demonstrated CIA Controls

| Scene | Feature | CIA Pillar | Verified Control |
|---|---|---|---|
| 1 | MFA Login & Vault Intake | Confidentiality & Integrity | Argon2id + TOTP, AES-256-GCM chunked vault storage, SHA-256 pre-intake hashing |
| 2 | Hash Chain Custody | Integrity | Immutable append-only custody log with SHA-256 backward linkage |
| 3 | Anti-Tamper Triggers | Integrity | SQLite `BEFORE UPDATE/DELETE` triggers + chain verification pinpointing broken link |
| 4 | Storage Watchdog | Availability & Integrity | Proactive detection of disk-level bit-rot or offline tampering; quarantine mark |
| 5 | Threat Detection & IOCs | Integrity & Confidentiality | Exact line-indexed regex parser, defanged IOCs, UTC unified timeline |
| 6 | Sec 63 BSA Report | Integrity | Ed25519 digital signature + Section 63 BSA certificate embedding head hash |
| 7 | Report Tamper Check | Integrity | Immediate public verification flagging any post-export PDF alteration |
