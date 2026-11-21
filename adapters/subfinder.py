"""Subfinder parser (engine of 07 SubdomainScan): JSON lines {"host": ..., "source": ...}."""

from __future__ import annotations

import json
from pathlib import Path

from adapters._output import stored_counts
from core.findings import Confidence, Finding, ResultKind
from core.modules import ParseResult
from core.validation import TargetType, ValidationError, validate_target

MODULE_NAME = "SubdomainScan"
MAX_NAMES = 2000


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    hosts: dict[str, set[str]] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            host, source = str(entry.get("host", "")), str(entry.get("source", ""))
        except (ValueError, AttributeError):
            host, source = line, ""
        try:
            host = validate_target(TargetType.DOMAIN, host)
        except ValidationError:
            continue
        if target and not host.endswith("." + target):
            continue
        hosts.setdefault(host, set()).update({source} if source else set())
    findings = [
        Finding(module=MODULE_NAME, title=f"Subdomain {host}", value=host, source="Subfinder",
                confidence=Confidence.MEDIUM, result=ResultKind.FOUND, raw_ref="run.log",
                notes=("Seen in passive sources" + (f": {', '.join(sorted(sources))}" if sources else "")
                       + ". It may no longer exist or resolve."))
        for host, sources in sorted(hosts.items())[:MAX_NAMES]
    ]
    return ParseResult(findings, stored_counts(MAX_NAMES, found=len(hosts)))
