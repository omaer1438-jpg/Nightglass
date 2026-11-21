# Changelog

## 1.0.0 — 2026-11-20

### Added
- **Case Map**: an investigation board in every case (Map tab, Open map button).
  - Pinned cards for the case, its targets, findings, sources and evidence. Sagging strings for "found by", "via", evidence and shared values (username, email, domain, IP, URL, image SHA-256 or dHash).
  - Sticky notes and analyst strings, pin/lock, Focus mode, filters and search, re-layout.
  - PNG and SVG export. The board is also included in HTML and Markdown reports.
  - The board updates live, and its layout is saved per case (migration 3, `board_items`).
- **New modules:**
  - 26 PhoneRegistration (ignorant; active, off by default).
  - 27 InstagramPage (public profile, no login).
  - 28 Osintgram (your own Instagram login from Credential Manager, deleted after each run; target-focused commands only).
- **ImageMeta** now stores a perceptual hash (`dhash:`), computed with Qt only.
- **Reports:**
  - New sections: header, targets, sources and runs, consents, evidence re-check, limitations listing failed runs.
  - A `.sha256` sidecar file is written next to each report.
  - Redaction applies everywhere, including CSV. CSV cells are guarded against formula injection.
- **Shortcuts:** Ctrl+K, Ctrl+N, Ctrl+F, Ctrl+1–9. Empty states with "Clear filters". Error messages say how to fix the problem.
- **Version info:** the exe carries it, and `build.py` runs `--self-check` after every build.

### Fixed — safety
- The active-module scope is matched by whole token. `192.0.2.1` no longer passes for `192.0.2.10`, nor `example.com` for `notexample.com`, `www.` or `.au` variants.
- A single-instance lock stops two copies from overwriting the encrypted database.
- Case data no longer lands in `envs/`. The relative data dir is resolved, and files a tool writes next to itself are moved into the run.
- Redirects never reach private addresses and drop API-key headers on another host.
- IPv6 zone ids are refused. So are `.bat`/`.cmd`/`.ps1` executables and the `{other}` placeholder.
- ExifTool's whole `exiftool_files` folder is hash-pinned and checked at startup and before each run.
- Changing retention asks first and touches only cases that use the default.

### Fixed — reliability
- A run always finishes, even if its case is deleted mid-run. A parse error no longer hides the real timeout or crash reason, and a failing tool shows its own error line.
- Unreachable sources, 429 and 5xx responses fail the run with the provider's reason instead of reporting "0 findings".
- Sherlock run offline no longer floods the case.
- Oversized fields are truncated instead of dropping the whole run.
- Blackbird no longer loses wrapped results.
- SpiderFoot's stderr noise goes to `stderr.log`.
- Encryption (EFS) and evidence hashing, copying and verifying run off the GUI thread.
- Evidence can be linked to a finding. Re-adding a file never deletes a stored copy.

### Fixed — UI and performance
- Empty-state text is no longer clipped. Uncertain shows in blue. Disabled danger buttons look disabled.
- Content width now matches the prototype. Modals dim the window behind them. Settings icons and column balance are fixed. No horizontal scrolling in Modules.
- Large cases are faster:
  - Findings table: 2000 rows in 0.16 s.
  - Run console: 20,000 lines in 0.13 s.
  - Browser links: open in 0.2 s.
  - Catalog reload and tool check no longer block the UI.
  - The report preview renders only while Reports is visible.
- The timeout setting is now "Timeout limit", defaulting to each tool's own limit.

### Build
- About 38 MB of unused Qt DLLs and the bundled pygments/setuptools/_pytest were removed (`_internal` is now 55 MB).

### Known limits
See README › Known limitations.
