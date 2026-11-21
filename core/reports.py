"""Report export: HTML, Markdown and CSV, with optional redaction (plan week 8).

Reports separate verified findings from leads, list targets, module runs, consents, timestamps,
evidence hashes and limitations. Nothing is sent anywhere: files are written to the case's local
reports folder (or wherever the user chooses), each with a <name>.sha256 integrity file beside it.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import html
import io
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from core import __version__
from core.casemap import build_graph, load_board
from core.cases import CaseManager
from core.db import Database
from core.evidence import EvidenceStore
from core.findings import FindingStatus, FindingStore, ResultKind, StoredFinding
from core.runs import ConsentLog, RunStore, case_dir

FORMATS = {"html": "HTML", "md": "Markdown", "csv": "CSV"}

LIMITATIONS = [
    "Every result is a lead until a person checks it. Only findings marked Verified were confirmed manually.",
    "A username or email match does not prove account ownership or identity.",
    "No result does not prove that an account or record does not exist.",
    "Tools can be wrong or out of date: sites change, so false matches and misses happen.",
    "IP geolocation shows the approximate location of a network or ISP, not of a person.",
    "Phone carrier data reflects the original allocation; ported numbers may show the wrong carrier.",
    "External services may be incomplete, rate-limited or out of date at collection time.",
]

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<![\w.])\+\d[\d ()-]{6,18}\d")
_IP_CANDIDATE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:.]{3,45}(?![\w:.])")
# Folders of a Windows path (C:\Users\...\ or \\server\share\...): older evidence descriptions stored them.
_LOCAL_DIRS = re.compile(r'(?:[A-Za-z]:|\\\\[^\\/\s]+)[\\/](?:[^\\/:*?"<>|\r\n]*[\\/])*')


class ReportError(Exception):
    """Shown to the user."""


@dataclass
class ReportOptions:
    fmt: str = "html"
    include_verified: bool = True
    include_leads: bool = True
    include_rejected: bool = False
    include_info: bool = True
    include_sources: bool = True
    include_hashes: bool = True
    include_limitations: bool = True
    redact_contacts: bool = True
    redact_ips: bool = False
    include_map: bool = True  # case map image (rendered by the app) + analyst notes and strings


def redact(text: str | None, options: ReportOptions) -> str:
    if not text:
        return ""
    if options.redact_contacts:
        text = _EMAIL.sub("[redacted email]", text)
        text = _PHONE.sub("[redacted phone]", text)
    if options.redact_ips:
        text = _IP_CANDIDATE.sub(_redact_ip, text)
    return text


def _redact_ip(match: re.Match) -> str:
    """Only real IPv4/IPv6 addresses (validated), so hashes and dates stay readable."""
    try:
        ipaddress.ip_address(match.group(0))
    except ValueError:
        return match.group(0)
    return "[redacted IP]"


@dataclass
class ReportData:
    case: object
    findings: list[StoredFinding]
    evidence: list
    consents: list                                            # ConsentRecord, oldest first
    generated: datetime
    targets: list = field(default_factory=list)
    runs: list = field(default_factory=list)                  # RunRecord, oldest first
    finding_titles: dict[int, str] = field(default_factory=dict)  # every finding of the case, for evidence links
    checks: tuple[datetime, dict] | None = None               # (when, {evidence id: True/False/None})
    map_png: bytes | None = None
    map_file: str | None = None                               # Markdown: the sibling PNG's name
    board_notes: list[str] = field(default_factory=list)
    board_links: list[tuple[str, str, str]] = field(default_factory=list)  # (card, label, card)


# display_status -> section heading, in report order
GROUPS = {
    "Verified": "Verified findings",
    "Lead": "Leads — not verified",
    "Uncertain": "Uncertain — not verified",
    "Info": "Info (descriptive data) — not verified",
    "Rejected": "Rejected",
}


def collect(db: Database, case_id: int, options: ReportOptions,
            checks: tuple[datetime, dict] | None = None) -> ReportData:
    manager = CaseManager(db)
    case = manager.get_case(case_id)
    wanted = set()
    if options.include_verified:
        wanted.add(FindingStatus.VERIFIED)
    if options.include_leads:
        wanted.add(FindingStatus.LEAD)
    if options.include_rejected:
        wanted.add(FindingStatus.REJECTED)
    every = FindingStore(db).list(case_id)
    findings = [f for f in every if f.status in wanted
                and (options.include_info or f.result is not ResultKind.INFO)]
    order = list(GROUPS)
    findings.sort(key=lambda f: (order.index(f.display_status), f.module, f.title))
    data = ReportData(
        case=case, findings=findings,
        evidence=EvidenceStore(db).list(case_id) if options.include_hashes else [],
        consents=ConsentLog(db).list(case_id)[::-1],
        generated=datetime.now(timezone.utc).replace(microsecond=0),
        targets=manager.list_targets(case_id), runs=RunStore(db).list(case_id)[::-1],
        finding_titles={f.id: f.title for f in every}, checks=checks,
    )
    if options.include_map:
        board = load_board(db, case_id)
        nodes = build_graph(db, case_id, board).nodes
        shown = {f"f:{f.id}" for f in findings}

        def allowed(key: str) -> bool:
            """A link is printed only if the options let both of its cards into the report."""
            if key.startswith("f:"):
                return key in shown
            if key.startswith("s:"):
                return options.include_sources
            if key.startswith("e:"):
                return options.include_hashes
            return True

        data.board_notes = [n.text for n in board.notes if n.text]
        data.board_links = [(nodes[l.a_key].label, l.label, nodes[l.b_key].label) for l in board.links
                            if l.a_key in nodes and l.b_key in nodes and allowed(l.a_key) and allowed(l.b_key)]
    return data


def _local(dt: datetime) -> str:
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


def _target_shown(target) -> str:
    """A file target is shown by name: its local path holds the Windows user name."""
    return PureWindowsPath(target.value).name if target.type.value == "file" else target.value


def _utc(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def _status_label(f: StoredFinding) -> str:
    status = f.display_status
    return status if status in ("Verified", "Rejected") else f"{status} — not verified"


def _run_ref(run_id: int | None) -> str:
    return f"r-{run_id:04d}" if run_id else "—"


def _run_status(status: str) -> str:
    return status.replace("_", " ").capitalize()


def _yes(flag: bool) -> str:
    return "Yes" if flag else "No"


def _csv_safe(value: str) -> str:
    """Stop spreadsheet formula injection from collected text."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def render(db: Database, case_id: int, options: ReportOptions, map_png: bytes | None = None,
           map_file: str | None = None, checks: tuple[datetime, dict] | None = None) -> str:
    """map_png: the case map image, rendered by the app (core stays Qt-free). HTML embeds it;
    Markdown links map_file, the PNG that export() writes next to the report.
    checks: (when, {evidence id: check_file() result}) from a hash re-check the app ran off the GUI thread."""
    if options.fmt not in FORMATS:
        raise ReportError(f"Unknown format: {options.fmt}")
    data = collect(db, case_id, options, checks)
    if options.include_map:
        data.map_png, data.map_file = map_png, map_file
    return {"html": _html, "md": _markdown, "csv": _csv}[options.fmt](data, options)


MAP_CAPTION = "Case map. Connections are leads until verified; a shared value is not proof of identity."
BANNER = ("Leads are not verified and are not proof of identity. "
          "Only findings marked Verified were confirmed manually.")


def _board_lines(data: ReportData, o: ReportOptions) -> list[str]:
    lines = [f"Note: {redact(text, o)}" for text in data.board_notes]
    lines += [f"Connection: {redact(a, o)} ↔ {redact(b, o)}" + (f" — {redact(label, o)}" if label else "")
              for a, label, b in data.board_links]
    return lines


def _facts(data: ReportData) -> list[tuple[str, str]]:
    case = data.case
    return [
        ("Case", case.ref), ("Name", case.name), ("Purpose", case.purpose),
        ("Authorized scope", case.authorized_scope), ("Status", case.status.capitalize()),
        ("Created (UTC)", _utc(case.created_at)), ("Closed (UTC)", _utc(case.closed_at) or "—"),
        ("Report generated", f"{_utc(data.generated)} UTC ({_local(data.generated)} local)"),
        ("Nightglass version", __version__),
        ("In this report", f"{len(data.findings)} findings · {len(data.runs)} runs · {len(data.consents)} logged consents"),
    ]


def _finding_row(f: StoredFinding, o: ReportOptions) -> list:
    row = [f.title, f.value or "", f.url or "", f.module]
    if o.include_sources:
        row += [f.source, _utc(f.collected_at), f.confidence.value]
    return row + [_status_label(f), f.notes]


def _limitations(data: ReportData) -> list[str]:
    broken = [f"{r.module or r.tool_id or 'unknown module'} ({_run_ref(r.id)}, {_run_status(r.status).lower()})"
              for r in data.runs if r.status in ("failed", "timed_out", "cancelled")]
    return LIMITATIONS + ["Runs that failed, timed out or were cancelled in this case, so their results may be "
                          "missing: " + "; ".join(broken) + "." if broken
                          else "No module run failed or timed out in this case."]


def _tables(data: ReportData, o: ReportOptions) -> list[tuple[str, list[str], list[list], str]]:
    """(heading, columns, rows, note) with raw values: each renderer redacts and escapes every cell."""
    tables = [("Targets", ["Type", "Value"], [[t.type.value, _target_shown(t)] for t in data.targets], "")]
    columns = ["Finding", "Value", "URL", "Module"]
    if o.include_sources:
        columns += ["Source", "Collected (UTC)", "Confidence"]
    columns += ["Status", "Verification note"]
    for key, heading in GROUPS.items():
        rows = [_finding_row(f, o) for f in data.findings if f.display_status == key]
        if rows:
            tables.append((heading, columns, rows, ""))
    if o.include_sources:
        providers: dict[int, set[str]] = {}
        for item in [*data.findings, *data.consents]:
            if item.run_id:
                providers.setdefault(item.run_id, set()).add(getattr(item, "provider", None) or item.source)
        tables.append(("Sources", ["Run", "Module", "Tool / provider", "Started (UTC)", "Ended (UTC)", "Run status",
                                   "External", "Active"],
                       [[_run_ref(r.id), r.module or "", ", ".join(sorted(providers.get(r.id, ()))) or r.tool_id or "",
                         _utc(r.started_at), _utc(r.ended_at), _run_status(r.status), _yes(r.external_network),
                         _yes(r.active)] for r in data.runs],
                       "Every module run in this case."))
        tables.append(("Consents", ["Consent", "Run", "Module", "Provider", "Data sent", "Consented (UTC)", "Active",
                                    "Scope confirmed", "Remembered"],
                       [[c.ref, _run_ref(c.run_id), c.module, c.provider, c.data_sent, _utc(c.consented_at),
                         _yes(c.active), _yes(c.scope_confirmed), _yes(c.remembered)] for c in data.consents],
                       "What was sent to which external provider, as confirmed in the consent dialog."))
    if data.evidence:
        columns = ["File", "SHA-256", "Collected (UTC)", "Linked finding", "Description"]
        note = "File names only; the files stay in the case folder."
        if data.checks:
            columns.append("Hash re-check")
            note += f" Re-checked against the stored files at {_utc(data.checks[0])} UTC."
        rows = []
        for item in data.evidence:
            row = [item.name, item.sha256, _utc(item.collected_at),
                   data.finding_titles.get(item.finding_id, "—") if item.finding_id else "—",
                   _LOCAL_DIRS.sub("", item.description)]
            if data.checks:
                row.append({True: "Matches", False: "CHANGED", None: "Missing"}.get(
                    data.checks[1].get(item.id, "?"), "Not checked"))
            rows.append(row)
        tables.append(("Evidence (SHA-256)", columns, rows, note))
    return tables


def _csv(data: ReportData, o: ReportOptions) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    columns = ["finding_id", "title", "value", "url", "module"]
    if o.include_sources:
        columns += ["source", "collected_at_utc", "confidence"]
    writer.writerow(columns + ["status", "verification_notes", "run_id"])
    for f in data.findings:
        row = [f.id, *_finding_row(f, o), f.run_id or ""]
        writer.writerow([_csv_safe(redact(str(v), o)) for v in row])
    return out.getvalue()


def _markdown(data: ReportData, o: ReportOptions) -> str:
    md = lambda s: redact(str(s), o).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    lines = [f"# {md(data.case.name)}", ""] + [f"- **{k}:** {md(v)}" for k, v in _facts(data)]
    lines += ["", f"> {BANNER}"]
    if o.include_map and data.map_png:
        lines += ["", "## Case map", ""]
        lines += [f"![Case map](<{data.map_file}>)" if data.map_file
                  else "_The map image is saved next to this report when you export it._", "", f"_{MAP_CAPTION}_"]
    board = _board_lines(data, o)
    if o.include_map and board:
        lines += ["", "## Analyst notes and links", ""] + [f"- {md(line)}" for line in board]
    for heading, columns, rows, note in _tables(data, o):
        lines += ["", f"## {heading}", ""] + ([f"_{note}_", ""] if note else [])
        if not rows:
            lines.append("_None recorded._")
            continue
        header = "| " + " | ".join(columns) + " |"
        lines += [header, header_rule(header)] + ["| " + " | ".join(md(v) for v in row) + " |" for row in rows]
    if o.include_limitations:
        lines += ["", "## Limitations", ""] + [f"- {md(item)}" for item in _limitations(data)]
    return "\n".join(lines) + "\n"


def header_rule(header: str) -> str:
    return "|" + "---|" * (header.count("|") - 1)


_CSS = """
body{font:14px/1.5 "Segoe UI",system-ui,sans-serif;color:#16202b;background:#f4f6f8;margin:0;padding:32px}
main{max-width:1100px;margin:auto;background:#fff;border-radius:8px;padding:28px 32px;box-shadow:0 4px 18px rgba(0,0,0,.08)}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:26px 0 8px;border-bottom:1px solid #dbe2e8;padding-bottom:4px}
.m{color:#5a6a7a;font-size:12px} table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;border-bottom:1px solid #dbe2e8;padding:6px 8px;vertical-align:top}
th{color:#5a6a7a;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.facts th{width:180px;text-transform:none;font-size:12px;letter-spacing:0}
.lead{color:#9a6400;font-weight:600} .ver{color:#18794e;font-weight:600} .rej{color:#7d8ea2}
code{font:12px Consolas,monospace;word-break:break-all}
.banner{background:#fff7e6;border:1px solid #f0d9a8;border-radius:6px;padding:8px 12px;font-size:12.5px;margin-top:14px}
"""

_STATUS_CLASS = {"Verified": "ver", "Rejected": "rej"}
_MONO = {"Value", "URL", "SHA-256", "Run", "Consent"}


def _html(data: ReportData, o: ReportOptions) -> str:
    e = lambda s: html.escape(redact(str(s or ""), o))  # noqa: E731

    def cell(column: str, value) -> str:
        if column == "Status":
            return f"<td class='{_STATUS_CLASS.get(value, 'lead')}'>{e(value)}</td>"
        return f"<td><code>{e(value)}</code></td>" if column in _MONO and value else f"<td>{e(value)}</td>"

    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='referrer' content='no-referrer'>",
        f"<title>{e(data.case.name)} — {e(data.case.ref)}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{e(data.case.name)}</h1><div class='m'>Private report</div>",
        "<table class='facts'>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in _facts(data))
        + "</table>",
        f"<div class='banner'>{e(BANNER)}</div>",
    ]
    if o.include_map and data.map_png:
        image = base64.b64encode(data.map_png).decode("ascii")
        parts.append(f"<h2>Case map</h2><img src='data:image/png;base64,{image}' alt='Case map' "
                     f"style='max-width:100%;border-radius:6px'><p class='m'>{MAP_CAPTION}</p>")
    board = _board_lines(data, o)
    if o.include_map and board:
        parts.append("<h2>Analyst notes and links</h2><ul>"
                     + "".join(f"<li>{html.escape(line)}</li>" for line in board) + "</ul>")
    for heading, columns, rows, note in _tables(data, o):
        parts.append(f"<h2>{e(heading)}</h2>" + (f"<p class='m'>{e(note)}</p>" if note else ""))
        if not rows:
            parts.append("<p class='m'>None recorded.</p>")
            continue
        parts.append("<table><tr>" + "".join(f"<th>{e(c)}</th>" for c in columns) + "</tr>")
        parts += ["<tr>" + "".join(cell(c, v) for c, v in zip(columns, row)) + "</tr>" for row in rows]
        parts.append("</table>")
    if o.include_limitations:
        parts.append("<h2>Limitations</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in _limitations(data)) + "</ul>")
    parts.append("</main></body></html>")
    return "\n".join(parts)


def default_path(case_id: int, ref: str, fmt: str, root: Path | None = None) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return case_dir(case_id, root) / "reports" / f"{ref}-report-{stamp}.{fmt}"


def sidecar(path: Path) -> Path:
    """<name>.sha256 next to the report, in sha256sum format."""
    return path.with_name(path.name + ".sha256")


def export(db: Database, case_id: int, options: ReportOptions, path: Path, map_png: bytes | None = None,
           checks: tuple[datetime, dict] | None = None) -> Path:
    """Write the report and its SHA-256 sidecar. Markdown gets the map as a sibling <stem>-map.png;
    HTML embeds it."""
    path = Path(path)
    sibling = path.with_name(f"{path.stem}-map.png") if options.fmt == "md" and options.include_map and map_png else None
    content = render(db, case_id, options, map_png, sibling.name if sibling else None, checks)
    raw = content.encode("utf-8-sig" if options.fmt == "csv" else "utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if sibling is not None:
            sibling.write_bytes(map_png)
        path.write_bytes(raw)
        sidecar(path).write_text(f"{hashlib.sha256(raw).hexdigest()}  {path.name}\n", encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ReportError(f"Could not save the report: {exc.strerror or exc}.") from exc
    return path
