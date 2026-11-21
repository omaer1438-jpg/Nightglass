"""theHarvester parser (engine of 07 SubdomainScan): report.json in the run folder (-f report).

{"hosts": ["www.example.com:192.0.2.10", "mail.example.com"], "emails": ["owner@example.com"], ...}
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters._output import stored_counts, unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ParseResult
from core.validation import TargetType, ValidationError, validate_target

MODULE_NAME = "SubdomainScan"
SOURCE = "theHarvester"
MAX_NAMES = 2000
HOST_NOTE = "Seen in passive sources. It may no longer exist or resolve."
EMAIL_NOTE = "Public address seen in passive sources. Not proof of who uses it."


@unexpected_output("theHarvester")
def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    report = Path(work_dir) / "report.json" if work_dir else None
    data = json.loads(report.read_text(encoding="utf-8") or "{}") if report and report.is_file() else {}
    hosts = set()
    for entry in data.get("hosts", []):
        try:
            host = validate_target(TargetType.DOMAIN, str(entry).split(":")[0])
        except ValidationError:  # wildcards and junk from certificate logs
            continue
        if not target or host.endswith("." + target):
            hosts.add(host)
    emails = sorted({str(e).lower() for e in data.get("emails", [])})
    findings = [Finding(module=MODULE_NAME, title=f"Subdomain {host}", value=host, source=SOURCE, raw_ref="report.json",
                        confidence=Confidence.MEDIUM, result=ResultKind.FOUND, notes=HOST_NOTE)
                for host in sorted(hosts)[:MAX_NAMES]]
    findings += [Finding(module=MODULE_NAME, title=f"Email {email}", value=email, source=SOURCE, raw_ref="report.json",
                         confidence=Confidence.MEDIUM, result=ResultKind.FOUND, notes=EMAIL_NOTE)
                 for email in emails[:MAX_NAMES]]
    return ParseResult(findings, stored_counts(MAX_NAMES, found=len(hosts), emails=len(emails)))
