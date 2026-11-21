"""PhoneInfoga parser (external engine of 03 PhoneIntel).

    Results for local
    Raw local: 5550100123
    E164: +15550100123
    Results for googlesearch
    Social media:
        URL: https://www.google.com/search?q=...
"""

from __future__ import annotations

import re
from pathlib import Path

from core.findings import Confidence, Finding, ResultKind
from core.modules import ParseResult

MODULE_NAME = "PhoneIntel"
_SECTION = re.compile(r"^Results for (?P<scanner>[\w-]+)")
_PAIR = re.compile(r"^(?P<key>[A-Za-z][\w ()/-]{0,40}):\s*(?P<value>.+)$")
MAX_LINKS = 15


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    findings: list[Finding] = []
    scanner, group, links, scanners = "", "", 0, set()
    for raw in lines:
        line = raw.strip()
        section = _SECTION.match(line)
        if section:
            scanner, group = section["scanner"], ""
            scanners.add(scanner)
            continue
        if not scanner or not line:
            continue
        if line.endswith(":") and not raw.startswith((" ", "\t")):
            group = line[:-1]
            continue
        pair = _PAIR.match(line)
        if not pair:
            continue
        key, value = pair["key"].strip(), pair["value"].strip()
        if key == "URL" and value.startswith("https://"):
            if links >= MAX_LINKS:
                continue
            links += 1
            findings.append(Finding(module=MODULE_NAME, title=f"Search link: {group or scanner}", value=value,
                                    url=value, source=f"PhoneInfoga {scanner}", confidence=Confidence.LOW,
                                    result=ResultKind.INFO, notes="A search to run yourself, not a result."))
            continue
        findings.append(Finding(module=MODULE_NAME, title=f"{key} ({scanner})", value=value[:4000],
                                source=f"PhoneInfoga {scanner}",
                                confidence=Confidence.HIGH if scanner == "local" else Confidence.MEDIUM,
                                result=ResultKind.INFO))
    return ParseResult(findings, {"scanners": len(scanners), "facts": len(findings) - links, "links": links})
