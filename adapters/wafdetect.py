"""24 WafDetect (ACTIVE, off by default): which web application firewall protects a site (wafw00f).

wafw00f writes waf.json into the run folder: [{"url": ..., "detected": true, "firewall": ..., "manufacturer": ...}]
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.validation import TargetType

NAME = "WafDetect"
SOURCE = "wafw00f"


@unexpected_output("wafw00f")
def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    report = Path(work_dir) / "waf.json" if work_dir else None
    rows = json.loads(report.read_text(encoding="utf-8") or "[]") if report and report.is_file() else []

    def finding(title, value, result=ResultKind.INFO, notes=""):
        return Finding(module=NAME, title=title, value=value, source=SOURCE, confidence=Confidence.MEDIUM, result=result,
                       raw_ref="waf.json", notes=notes)

    if not rows:
        if any("appears to be down" in line for line in lines):  # wafw00f's own message
            return ParseResult([finding("Site not reachable", target, notes="wafw00f could not load the page.")],
                               {"found": 0})
        raise ValueError("wafw00f wrote no results.")  # crashed or was stopped: the run status says why
    detected = [row for row in rows if row.get("detected")]
    findings = [finding("Firewall detected", f"{row.get('firewall')} ({row.get('manufacturer')})", ResultKind.FOUND)
                for row in detected]
    return ParseResult(findings or [finding("No firewall identified", target, notes="One may still be in place.")],
                       {"found": len(detected)})


MODULE = ModuleSpec(
    number="24",
    id="wafdetect",
    name=NAME,
    icon="shield",
    description="Identifies the web application firewall in front of a site.",
    labels=("external", "active", "oss"),
    target_types=(TargetType.URL,),
    provider="The target site itself (a few test requests)",
    tools=("wafw00f",),
    active_setting="active.wafw00f",
    timeout_s=60,
    notes="It sends requests that look like attacks so the firewall reacts. Use it only on sites you may test.",
)
