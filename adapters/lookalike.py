"""19 LookalikeDomains: registered names that imitate a domain (dnstwist).

dnstwist prints one JSON array: [{"domain": "examp1e.com", "fuzzer": "homoglyph", "dns_a": ["192.0.2.10"]}, ...]
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.validation import TargetType

NAME = "LookalikeDomains"
NOTE = "Registered and similar to the target. Not proof of bad intent: check who runs it."


@unexpected_output("dnstwist")
def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    text = "\n".join(lines)
    if "[" not in text:
        if not text.strip():  # with --registered, dnstwist prints nothing when no look-alike is registered
            return ParseResult([], {"found": 0})
        first = next(line.strip() for line in lines if line.strip())
        raise ValueError(f"dnstwist printed no results: {first[:200]}")
    rows = json.loads(text[text.index("["):text.rfind("]") + 1])
    findings = []
    for row in rows:
        if row.get("fuzzer") == "*original":
            continue
        records = [f"{key.removeprefix('dns_').upper()}: {', '.join(row[key])}"
                   for key in ("dns_a", "dns_aaaa", "dns_mx", "dns_ns") if row.get(key)]
        findings.append(Finding(module=NAME, title=f"Lookalike {row['domain']}", value=row["domain"], source="dnstwist",
                                confidence=Confidence.LOW, result=ResultKind.FOUND, raw_ref="run.log",
                                notes=" ".join([NOTE, f"Method: {row.get('fuzzer')}.", *records])[:4000]))
    return ParseResult(findings, {"found": len(findings)})


MODULE = ModuleSpec(
    number="19",
    id="lookalike",
    name=NAME,
    icon="globe",
    description="Registered domains that imitate yours, for spotting phishing and impersonation.",
    labels=("external", "passive", "oss"),
    target_types=(TargetType.DOMAIN,),
    provider="Your DNS resolver (it looks up each similar name)",
    tools=("dnstwist",),
    timeout_s=300,
    max_output_kb=4096,
    notes="Finds names only. It never visits the sites.",
)
