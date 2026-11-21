"""22 URLScan: existing public urlscan.io scans of a site. It never submits a new scan, so nothing becomes public."""

from __future__ import annotations

from adapters._output import unexpected_output
from adapters._web import host_of
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "URLScan"
API = "https://urlscan.io/api/v1/search/"
MAX_SCANS = 10


@unexpected_output("urlscan.io")
def run(ctx) -> list[Finding]:
    host = host_of(ctx.target_type, ctx.target)
    ctx.emit(f"[i] urlscan.io search for {host}")
    data = ctx.http().get_json("urlscan", API, params={"q": f"page.domain:{host}", "size": MAX_SCANS}) or {}
    scans = data.get("results") or []
    if not scans:
        ctx.emit("[-] no public scan of this site")
        return [Finding(module=NAME, title="No public scan", value=host, source="urlscan.io", confidence=Confidence.MEDIUM,
                        result=ResultKind.INFO, notes="No result does not mean the site is safe.")]
    findings = []
    for scan in scans:
        page, task = scan.get("page") or {}, scan.get("task") or {}
        day = str(task.get("time"))[:10]
        details = [f"{label}: {page[key]}" for key, label in (
            ("title", "Page title"), ("ip", "IP"), ("asnname", "Network"), ("country", "Country"), ("server", "Server"))
            if page.get(key)]
        link = f"https://urlscan.io/result/{task.get('uuid')}/"
        ctx.emit(f"[+] {day}  {page.get('url')}  {page.get('ip') or ''}")
        findings.append(Finding(module=NAME, title=f"Scan on {day}", value=str(page.get("url"))[:4000], url=link,
                                source="urlscan.io", confidence=Confidence.MEDIUM, result=ResultKind.INFO,
                                notes=" · ".join(details)[:4000]))
    ctx.emit(f"[i] showing {len(findings)} of {data.get('total', len(findings))} scans")
    return findings


MODULE = ModuleSpec(
    number="22",
    id="urlscan",
    name=NAME,
    icon="search",
    description="Past public scans of a site: its IP, network, title and a screenshot link.",
    labels=("external", "passive"),
    target_types=(TargetType.DOMAIN, TargetType.URL),
    provider="urlscan.io (search of existing public scans)",
    run=run,
    timeout_s=45,
    notes="It reads past scans and never starts a new one, so your target stays private.",
)
