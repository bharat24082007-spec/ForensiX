# ADDENDUM TO THE MASTER PROMPT (read fully; where it conflicts with the master prompt, this addendum wins)

Save this file as docs/ADDENDUM.md and re-read it before every section.
Apply it retroactively to everything built so far, then continue with the current section.

=====================================================
PART A. FRONTEND VISIBILITY RULE
=====================================================
Every feature must be visible and usable from the web UI. Nothing may exist only
as backend code, a test, or a CLI command.

A1. NAVIGATION
    Sidebar: Dashboard, Cases, Reports, Verify Report, System (Health, Backup, Tools).
    Case tabs: Overview, Evidence, Custody, Timeline, Analysis (Metadata, Network, Logs),
    IOCs, Reports.
A2. PLACEHOLDERS
    Sections not built yet still show their tab with a "Coming in Sx" empty state,
    so I can see the full product shape from day one.
A3. A BUTTON FOR EVERY ACTION
    Verify Chain, Verify Evidence, Run Watchdog Now, Withdraw evidence, Legal Hold toggle,
    Run Analysis (metadata / pcap / logs), Generate Report, Sign Report, Verify Report,
    Create Backup, Restore, Export Case.
    Each shows a job-status badge and a toast on success or failure.
A4. UI PROOF IN EVERY CHECKLIST
    Each "SECTION Sx COMPLETE" checklist must also list: the URL to open, the exact clicks
    to see the feature working, and what I should see on screen (chips, hashes, tables).
A5. DEMO MODE
    Dashboard "Load Demo Case" button (Admin or Lead only). It creates a sample case with
    the demo auth.log, EXIF image, fake photo.jpg, EICAR file, IOC text file and
    tools/demo/sample.pcap, so every tab has data.
A6. FEATURE MAP
    Dashboard card listing all 11 features with a status chip (Built / Not yet built)
    and an "Open" link to each.

=====================================================
PART B. CLEAR AND ATTRACTIVE FRONTEND PATH
=====================================================
B1. GUIDED FLOW
    Under every case header show a clickable stepper:
    1 Evidence > 2 Verify > 3 Analyse > 4 Timeline > 5 Report
    States: done (green tick), current (blue), not started (grey).
    Each page ends with one prominent "Next step" button (e.g. "Next: Verify integrity").
B2. "WHAT TO DO NEXT" CARD on the case Overview, one action only, e.g.
    "No evidence yet - Upload your first file" / "3 files unverified - Run integrity check"
    / "Analysis done - Generate report".
B3. LOGIN AND DASHBOARD
    Login: centered card, logo, tagline "Evidence you can verify".
    Dashboard: 4 stat tiles with icons, Feature Map cards (icon, name, one-line purpose,
    status chip, Open button), quick-action row: New Case, Upload Evidence,
    Verify Chain, Load Demo Case.
B4. VISUAL POLISH
    Navy sidebar, light content area, one accent colour (teal or indigo), 8px radius and
    8px grid, soft shadows, icons on every nav item and button (inline SVG sprite),
    150ms hover/focus transitions, skeleton loaders, no layout jumps, dark-mode toggle.
    Status chips use colour AND an icon, never colour alone.
B5. FORENSIC TOUCHES
    - Hash display: large monospace, copy button, verified-shield icon.
    - Custody log shown as a vertical timeline with coloured dots (table view optional).
    - Verify Chain animation: chain blocks light up green one by one; on a break, the
      broken block turns red and shows its entry number.
    - Chain drawn as linked boxes (Block 1 -> Block 2 -> ...).
B6. ORIENTATION
    Every page has breadcrumbs, a title, a one-line description, the active sidebar item
    and active tab highlighted.
B7. EMPTY STATES AND FEEDBACK
    Every empty table has an illustration, one sentence and a button.
    Every action gives a toast. Long actions show a progress or job badge.
B8. TECH LIMIT
    Vanilla CSS and JS only, locally vendored, no CDN, no new libraries, pure-CSS animation.

=====================================================
PART C. TECHNICAL AMENDMENTS
=====================================================
C1. S2 -> S5 HANDOFF
    In S2, mark every place a system-chain event must be logged with "# TODO(S5): custody.append".
    In S5, grep for these markers and wire them all. None may remain.
C2. KEY RECOVERY (S13)
    Backups must not rely on a key stored only in the folder being backed up.
    Add an "Export master key" action (Admin only): the key is encrypted with an Admin-chosen
    passphrase (Argon2id-derived key + AES-GCM) and downloaded as a separate file.
    Restore accepts that file plus the passphrase. Warn clearly in the UI that losing
    the master key means evidence cannot be decrypted.
C3. STRONGER CHAIN (S5)
    Each custody entry also stores an HMAC-SHA256 over its entry_hash, keyed by a key derived
    from the master key (HKDF, separate context label). verify_chain checks both the hash chain
    and the HMACs. State in docs/CIA.md that this stops someone with only database access
    from recomputing a valid chain, but not someone who also holds the master key.
C4. VISIBLE SIGNATURE (S12)
    The report's last page prints: the signed SHA-256, the signer name and public-key
    fingerprint, the signing date (UTC), and the chain_head_hash. Also keep the detached .sig.
C5. DUPLICATE EVIDENCE (S4)
    If a file's SHA-256 already exists in the same case, warn the user and require
    confirmation. Log the decision in the custody chain.
C6. python-magic FALLBACK (S4)
    If libmagic is unavailable, fall back to a small built-in magic-number table
    (MZ, ELF, PDF, PNG, JPEG, ZIP, GIF) and show a warning on the Tools page.
C7. DEPENDENCIES (S0)
    Pin exact versions in requirements.txt. Add a note in README.md on running pip-audit.
C8. SCOPE ORDER
    Build S0-S13 and S15 first. S14 (graph) only if everything else passes.
    In S10, build extraction and defanging first. Online reputation lookup is last
    and stays OFF by default.

=====================================================
PART D. WORKING RULES (unchanged, restated)
=====================================================
One section at a time. Print a 5-line plan, build, run tests, print "SECTION Sx COMPLETE"
(files, how to run, UI proof from A4, CIA controls), then STOP and wait for "next".
Use only approved libraries. No shell=True, no CDN, no secrets in code, no raw SQL
concatenation. Business logic in service.py, HTTP in routes.py.
