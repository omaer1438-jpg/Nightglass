"""SpiderFoot parser (engine of 07 SubdomainScan): one JSON event per console line (-o json).

[{"generated": 1, "type": "Internet Name", "data": "www.example.com", "module": "sfp_crt", "source": "example.com"},
{"generated": 2, "type": "Email Address", "data": "owner@example.com", "module": "sfp_crt", "source": "example.com"}]
A run cut short by the timeout still leaves whole lines, so each line is read on its own. Windows logging
errors from SpiderFoot's worker processes land in the same stream and are skipped.
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters._output import stored_counts
from core.findings import Confidence, Finding, ResultKind
from core.modules import ParseResult
from core.validation import TargetType, ValidationError, validate_target

MODULE_NAME = "SubdomainScan"
SOURCE = "SpiderFoot"
MAX_NAMES = 2000
HOST_NOTE = "Seen by SpiderFoot module {}. It may no longer exist or resolve."
EMAIL_NOTE = "Public address seen by SpiderFoot module {}. Not proof of who uses it."


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    hosts: dict[str, str] = {}
    emails: dict[str, str] = {}
    for line in lines:
        try:
            event, _ = json.JSONDecoder().raw_decode(line, line.index("{"))
            kind, value, module = event["type"], str(event["data"]), str(event.get("module", ""))
        except (ValueError, KeyError, TypeError):
            continue
        if kind == "Email Address":
            emails.setdefault(value.lower(), module)
        elif kind == "Internet Name":
            try:
                host = validate_target(TargetType.DOMAIN, value)
            except ValidationError:
                continue
            if not target or host.endswith("." + target):
                hosts.setdefault(host, module)
    findings = [Finding(module=MODULE_NAME, title=f"Subdomain {host}", value=host, source=SOURCE, raw_ref="run.log",
                        confidence=Confidence.MEDIUM, result=ResultKind.FOUND, notes=HOST_NOTE.format(module))
                for host, module in sorted(hosts.items())[:MAX_NAMES]]
    findings += [Finding(module=MODULE_NAME, title=f"Email {email}", value=email, source=SOURCE, raw_ref="run.log",
                         confidence=Confidence.MEDIUM, result=ResultKind.FOUND, notes=EMAIL_NOTE.format(module))
                 for email, module in sorted(emails.items())[:MAX_NAMES]]
    return ParseResult(findings, stored_counts(MAX_NAMES, found=len(hosts), emails=len(emails)))
