"""01 UserRecon: Sherlock output parser.

Sherlock 0.16 prints one line per site (--print-all --no-color):
  [+] GitHub: https://github.com/example_user      claimed  -> lead
  [-] Pinterest: Not Found!                         available
  [-] Instagram: Blocked by bot detection (...)     WAF      -> uncertain
  [-] Site: Illegal Username Format For This Site!  skipped
  [-] Site: <error context>                         unknown  -> uncertain
"""

from __future__ import annotations

import re
from pathlib import Path

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.validation import TargetType

_LINE = re.compile(r"^\[(?P<mark>[+\-*?])\]\s+(?P<site>[^:]+?):\s*(?P<rest>.*)$")
_NOT_FOUND = "Not Found!"
_ILLEGAL = "Illegal Username Format"
MODULE_NAME = "UserRecon"
MAX_UNCERTAIN = 100  # a normal run has ~60; more means mass errors, which would only bury the real leads
MIN_SITES = 20       # below this, a mostly-uncertain result proves nothing (short or cut-off run)


def classify(line: str) -> tuple[str, str, str]:
    """(kind, site, detail) with kind in found / not_found / uncertain / illegal / info."""
    match = _LINE.match(line.strip())
    if not match:
        return "info", "", line
    mark, site, rest = match["mark"], match["site"].strip(), match["rest"].strip()
    if mark == "+":
        return "found", site, rest
    if mark == "*":
        return "info", "", line
    if rest.startswith(_NOT_FOUND):
        return "not_found", site, rest
    if rest.startswith(_ILLEGAL):
        return "illegal", site, rest
    return "uncertain", site, rest


def console_tag(line: str) -> str:
    return {"found": "g", "uncertain": "b", "not_found": "p", "illegal": "p", "info": "c"}[classify(line)[0]]


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    findings: list[Finding] = []
    counts = {"found": 0, "uncertain": 0, "not_found": 0}
    seen: set[str] = set()
    for line in lines:
        kind, site, detail = classify(line)
        if kind not in counts or site in seen:
            continue
        seen.add(site)
        counts[kind] += 1
        if kind == "found":
            url = detail if detail.lower().startswith(("http://", "https://")) and " " not in detail else None
            findings.append(Finding(
                module=MODULE_NAME, title=f"{site} profile", value=url or detail, source="Sherlock", url=url,
                confidence=Confidence.MEDIUM, result=ResultKind.FOUND, raw_ref="run.log",
                notes="Username match only. Not proof that the target owns this account.",
            ))
        elif kind == "uncertain" and counts["uncertain"] <= MAX_UNCERTAIN:
            findings.append(Finding(
                module=MODULE_NAME, title=site, value=detail[:300] or "No clear answer", source="Sherlock",
                confidence=Confidence.LOW, result=ResultKind.UNCERTAIN, raw_ref="run.log",
                notes="Blocked, rate-limited or ambiguous. Check manually if it matters.",
            ))
    checked = sum(counts.values())
    if counts["found"] == 0 and checked >= MIN_SITES and counts["uncertain"] >= 0.9 * checked:
        raise ValueError(f"No site could be reached: {counts['uncertain']} of {checked} sites gave no clear answer. "
                         "Check the network connection and try again.")
    if counts["uncertain"] > MAX_UNCERTAIN:
        counts[f"uncertain_not_stored_(limit_{MAX_UNCERTAIN})"] = counts["uncertain"] - MAX_UNCERTAIN
    return ParseResult(findings, counts)


MODULE = ModuleSpec(
    number="01",
    id="userrecon",
    name=MODULE_NAME,
    icon="user",
    description="Find public profiles for a username across hundreds of sites.",
    labels=("external", "passive", "oss"),
    target_types=(TargetType.USERNAME,),
    provider="About 400 public websites from Sherlock's bundled site list",
    tools=("sherlock", "maigret", "blackbird_username", "social_analyzer"),
    console_tag=console_tag,
    timeout_s=300,
    max_output_kb=2048,
    notes="Hits are leads; false positives are common.",
)
