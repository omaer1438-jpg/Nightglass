"""Holehe parser (active engine of 02 EmailFootprint).

With --only-used --no-color Holehe prints one line per site where the email appears registered:
    [+] instagram.com
    [+] example.com ex****@example.com / +1 5** *** **23
    [x] twitter.com            (rate limited)
    121 websites checked in 9.7 seconds
"""

from __future__ import annotations

import re
from pathlib import Path

from core.findings import Confidence, Finding, ResultKind
from core.modules import ParseResult

MODULE_NAME = "EmailFootprint"
_LINE = re.compile(r"^\[(?P<mark>[+x\-])\]\s+(?P<domain>[a-z0-9.-]+\.[a-z]{2,})(?P<extra>.*)$", re.I)
_CHECKED = re.compile(r"(?P<n>\d+)\s+websites checked")


def console_tag(line: str) -> str:
    return {"+": "g", "x": "b", "-": "p"}.get(line[1:2], "") if line.startswith("[") else ""


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    findings, seen = [], set()
    counts = {"found": 0, "rate_limited": 0}
    for line in lines:
        match = _LINE.match(line.strip())
        if match:
            domain = match["domain"].lower()
            if domain in seen:
                continue
            seen.add(domain)
            if match["mark"] == "+":
                counts["found"] += 1
                extra = match["extra"].strip()
                findings.append(Finding(
                    module=MODULE_NAME, title=f"Account on {domain}", value=domain, source="Holehe (active)",
                    confidence=Confidence.MEDIUM, result=ResultKind.FOUND, raw_ref="run.log",
                    notes=("The site's signup/login form reports this email as registered. Not proof of who "
                           "controls it." + (f" Partial recovery hints: {extra}" if extra else ""))[:4000],
                ))
            elif match["mark"] == "x":
                counts["rate_limited"] += 1
        checked = _CHECKED.search(line)
        if checked:
            counts["checked"] = int(checked["n"])
    return ParseResult(findings, counts)
