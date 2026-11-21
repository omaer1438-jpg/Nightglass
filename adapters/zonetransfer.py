"""25 ZoneTransfer (ACTIVE, off by default): does a domain's DNS server hand out its whole zone? (dnsrecon -t axfr)

    [*] Trying NS server 192.0.2.53
    [+] Zone Transfer was successful!!
    [*]      A www.example.com 192.0.2.10
    [-] Zone Transfer Failed (Zone transfer error: REFUSED)

Console output, because dnsrecon's JSON writer fails on zone records.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.validation import TargetType

NAME = "ZoneTransfer"
SOURCE = "dnsrecon"
MAX_RECORDS = 500
_RECORD = re.compile(r"^\[\*\]\s+(?P<kind>[A-Z0-9]{1,10})\s+(?P<value>\S.*)$")
OPEN_NOTE = "This server gives its whole zone to anyone. The owner should restrict zone transfers."
CLOSED_NOTE = "Every name server refused. This is the safe setting."
NOT_TESTED_NOTE = "dnsrecon found no name server to ask, so nothing was tested. See the run log for why."


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    servers = sum("Trying NS server" in line for line in lines)
    allowed = sum("Zone Transfer was successful" in line for line in lines)
    if not servers:  # offline, no such domain, or dnsrecon failed: nothing was tested, so no all-clear
        return ParseResult([Finding(module=NAME, title="No name server could be checked", value=target or "-",
                                    source=SOURCE, confidence=Confidence.LOW, result=ResultKind.UNCERTAIN,
                                    raw_ref="run.log", notes=NOT_TESTED_NOTE)], {"found": 0, "servers": 0})
    records, inside = [], False
    for line in lines:
        if "Zone Transfer was successful" in line:
            inside = True
        elif line.startswith(("[-]", "[+]")) or "Trying NS server" in line:
            inside = False
        elif inside:
            match = _RECORD.match(line.strip())
            if match and f"{match['kind']} {match['value']}" not in records:
                records.append(f"{match['kind']} {match['value']}")
    head = Finding(module=NAME, title="Zone transfer allowed" if allowed else "Zone transfer refused",
                   value=f"{allowed} of {servers} name servers", source=SOURCE, confidence=Confidence.HIGH, raw_ref="run.log",
                   result=ResultKind.FOUND if allowed else ResultKind.INFO, notes=OPEN_NOTE if allowed else CLOSED_NOTE)
    findings = [head] + [Finding(module=NAME, title=f"Zone record {record.split()[0]}", value=record.split(" ", 1)[1][:4000],
                                 source=SOURCE, confidence=Confidence.HIGH, result=ResultKind.INFO, raw_ref="run.log")
                         for record in records[:MAX_RECORDS]]
    return ParseResult(findings, {"found": allowed, "records": len(records)})


MODULE = ModuleSpec(
    number="25",
    id="zonetransfer",
    name=NAME,
    icon="dns",
    description="Checks whether a domain's name servers leak all their records.",
    labels=("external", "active", "oss"),
    target_types=(TargetType.DOMAIN,),
    provider="The target domain's own name servers",
    tools=("dnsrecon_axfr",),
    active_setting="active.zone_transfer",
    timeout_s=120,
    notes="It asks the target's servers directly. Use it only on domains you may test.",
)
