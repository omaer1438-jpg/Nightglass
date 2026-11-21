# Nightglass — project rules

Nightglass is a Windows desktop OSINT workbench (Python + PySide6). It organizes free and open-source OSINT
tools, runs built-in lookup modules safely, stores cases locally and exports reports. English UI (Arabic
available), dark mode.

## Stack
- Python 3.11+, PySide6 (Qt Widgets), QSS for styling
- SQLite (optional built-in AES-256-GCM encryption), `keyring` for API keys
- QProcess / QThread for all tool runs (the UI never blocks)
- pydantic for manifests and the Finding schema
- pytest + pytest-qt; PyInstaller for the Windows build
- Heavy tools (Sherlock, Maigret, Blackbird, Holehe, …) live in separate venvs under `envs/` and run as
  subprocesses, never bundled into the exe
- ExifTool: pinned binary in `bin/`, hash-checked at startup and before every run

## Project layout
```
app/        PySide6 UI: main window, screens, widgets, theme.qss
            screens/case_map.py + case_map_render.py: the Case Map board (Qt view, PNG/SVG export)
core/       case manager, db, runner, consent, exporters, finding schema
            casemap.py: Case Map graph model, string rules, layout, board storage (no Qt)
adapters/   one parser per tool/module (_output.py: shared "unexpected output" guard)
tools/      YAML manifests (tool catalog); tools/links/ = browser-only links
docs/       brand assets, screenshots, changelog
bin/        pinned binaries (git-ignored)
tests/      pytest; fixtures use fake data only
envs/ cases/ logs/ reports/   (git-ignored)
```

## Design tokens (Carbon Terminal)
- Window `#0c0c0c`, sidebar/bars `#090909`, surface `#141414`, raised `#1a1a1a`, hover `#222222`,
  border `#242424` / `#2e2e2e`, console `#050505`
- Text `#e8e8e3`, muted `#8a8a84`, dim `#5a5a56`
- Accent `#7ee787` (hover `#9af0a1`, pressed `#4caf5f`), the only interactive colour
- Labels: Local `#7ee787`, External `#ffb547`, Passive `#79c0ff`, Active `#ff6b6b` (danger only), API key `#d2a8ff`
- Status: Lead `#ffb547`, Verified `#7ee787`, Uncertain `#79c0ff`, Rejected `#5a5a56`
- Fonts: Segoe UI Variable / Segoe UI for UI text; JetBrains Mono (bundled) for console, hashes, URLs, IDs
- Radius 7–8 px controls, 10 px cards, 12 px dialogs; 1 px borders; custom title bar; 224 px sidebar

## Case Map (investigation board)
- **Source:** a per-case board built only from the database: cases, targets, findings, evidence and runs, plus
  `board_items`, which holds positions, sticky notes and analyst links.
- **No new collection:** the board never collects new data.
- **Code split:** the graph, string rules and layout are pure Python in `core/casemap.py`, unit-tested. The view is
  in `app/screens/case_map.py`.
- **String colours:** come only from `edge_tone()`. Red is reserved for active-module findings, and analyst
  strings are always leads.
- **Legend:** always says "Connections are leads until verified."

## Non-negotiable rules
1. **Never use a shell.** Tools run with argument lists from an allowlist in `tools/*.yaml`. No free-form
   input reaches a command.
2. Every run has a timeout, an output-size limit, its own work dir and a log.
3. **Validate input by type** (username, email, E.164 phone, IP, domain, URL, file) before it reaches any tool.
4. **External lookups need consent.** A dialog shows what data goes to which provider, and every consent is
   logged in the `consents` table.
5. **Active modules** (Holehe, phone app-registration check, port scan, WAF detection, zone transfer) are
   **off by default**. They are gated in Settings and checked against the case's authorized scope.
6. All results are `Finding` objects with status `lead | verified | rejected`. They stay leads until verified;
   a match is never presented as proof of identity.
7. Never store a target's passwords, cookies or tokens. API keys live only in `keyring`. Never commit secrets.
8. The UI and reports say "target" or "subject", never "victim".
9. Tests and fixtures use fake data only: `example_user`, `example.com`, documentation IPs (`192.0.2.0/24`,
   `203.0.113.0/24`) and `+1 555` numbers.

## Git hygiene
- `.gitignore` excludes `cases/ evidence/ reports/ logs/ envs/ *.db *.sqlite .env bin/*.exe`.
- A gitleaks pre-commit hook blocks secrets. Never commit case data.
- New tools are an adapter plus a manifest, with no core changes.
