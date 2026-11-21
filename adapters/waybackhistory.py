"""20 WaybackHistory: first and latest archived copy of a site, and the years it was archived (CDX API)."""

from __future__ import annotations

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "WaybackHistory"
API = "https://web.archive.org/cdx/search/cdx"
NOTE = "The first copy the archive holds. The site may be older."


def _date(stamp: str) -> str:
    return f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}"


@unexpected_output("the Wayback Machine")
def run(ctx) -> list[Finding]:
    http = ctx.http()

    def rows(**params):
        ctx.check()
        data = http.get_json("wayback", API, params={"url": ctx.target, "output": "json", **params}, timeout=30) or []
        return data[1:]  # the first row holds the column names

    ctx.emit(f"[i] Internet Archive lookup for {ctx.target}")
    first = rows(fl="timestamp,original", limit="1")
    if not first:
        ctx.emit("[-] the archive holds no copy of this address")
        return [Finding(module=NAME, title="No archived copy", value=ctx.target, source="Wayback Machine",
                        confidence=Confidence.MEDIUM, result=ResultKind.INFO,
                        notes="No result does not prove that the site never existed.")]
    last = rows(fl="timestamp,original", limit="-1")
    years = sorted({row[0][:4] for row in rows(fl="timestamp", collapse="timestamp:4")})
    findings = []
    for title, row, notes in (("First archived copy", first[0], NOTE), ("Latest archived copy", (last or first)[0], "")):
        link = f"https://web.archive.org/web/{row[0]}/{row[1]}"
        ctx.emit(f"[+] {title}: {_date(row[0])}")
        findings.append(Finding(module=NAME, title=title, value=_date(row[0]), url=link, source="Wayback Machine",
                                confidence=Confidence.HIGH, result=ResultKind.FOUND, notes=notes))
    ctx.emit(f"[+] Years with copies ({len(years)}): {', '.join(years)}")
    findings.append(Finding(module=NAME, title=f"Years with copies ({len(years)})", value=", ".join(years),
                            source="Wayback Machine", confidence=Confidence.HIGH, result=ResultKind.INFO))
    return findings


MODULE = ModuleSpec(
    number="20",
    id="waybackhistory",
    name=NAME,
    icon="rev",
    description="First and latest archived copy of a site, and the years it was archived.",
    labels=("external", "passive"),
    target_types=(TargetType.DOMAIN, TargetType.URL),
    provider="Internet Archive (Wayback Machine)",
    run=run,
    timeout_s=120,
)
