"""social-analyzer parser (engine of 01 UserRecon).

The last console line is one JSON document: {"detected": [{"link": ..., "rate": "%66.67", "title": ...}], ...}
Warnings from its HTML parser come before it.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ParseResult

MODULE_NAME = "UserRecon"
NOTE = "Detection score {}. Username match only. Not proof that the target owns this account."
SURE = 80.0


@unexpected_output("social-analyzer")
def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    report = next((line for line in reversed(lines) if line.lstrip().startswith("{")), "{}")
    findings = []
    for profile in json.loads(report).get("detected", []):
        link, rate = str(profile.get("link", "")), str(profile.get("rate", "")).lstrip("%")
        if not link.startswith(("http://", "https://")):
            continue
        site = (urlsplit(link).hostname or link).removeprefix("www.")
        sure = rate.replace(".", "", 1).isdigit() and float(rate) >= SURE
        findings.append(Finding(module=MODULE_NAME, title=f"{site} profile", value=link, url=link, source="social-analyzer",
                                confidence=Confidence.MEDIUM if sure else Confidence.LOW, result=ResultKind.FOUND,
                                raw_ref="run.log", notes=NOTE.format(f"{rate}%")))
    return ParseResult(findings, {"found": len(findings)})
