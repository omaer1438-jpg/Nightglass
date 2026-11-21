"""26 PhoneRegistration: ignorant's account-exists checks for a phone number. Active, off by default.

With --no-color --no-clear ignorant prints one line per site:
    [+] instagram.com      the form says the number is in use
    [-] snapchat.com       not in use
    [x] amazon.com         rate-limited, blocked or the check broke
    3 websites checked in 0.73 seconds
"""

from __future__ import annotations

import re
from pathlib import Path

from adapters._output import unreachable
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.validation import TargetType

NAME = "PhoneRegistration"
_LINE = re.compile(r"^\[(?P<mark>[+x\-])\]\s+(?P<domain>[a-z0-9.-]+\.[a-z]{2,})\s*$", re.I)
_CHECKED = re.compile(r"(?P<n>\d+)\s+websites checked")


def console_tag(line: str) -> str:
    return {"+": "g", "x": "b", "-": "p"}.get(line[1:2], "") if line.startswith("[") else ""


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    findings, seen = [], set()
    counts = {"found": 0, "not_found": 0, "not_checked": 0}
    for line in lines:
        match = _LINE.match(line.strip())
        if match and match["domain"].lower() not in seen:
            domain = match["domain"].lower()
            seen.add(domain)
            if match["mark"] == "+":
                counts["found"] += 1
                findings.append(Finding(
                    module=NAME, title=f"Number in use on {domain}", value=domain, source="ignorant (active)",
                    confidence=Confidence.LOW, result=ResultKind.FOUND, raw_ref="run.log",
                    notes="The site's login or signup check says this number is registered. A lead only: "
                          "not proof of who owns the number or the account."))
            elif match["mark"] == "x":
                counts["not_checked"] += 1
                findings.append(unreachable(NAME, domain, "Rate-limited, blocked, or the site changed its check."))
            else:
                counts["not_found"] += 1
        checked = _CHECKED.search(line)
        if checked:
            counts["checked"] = int(checked["n"])
    if not seen:
        raise ValueError("ignorant printed no site results.")
    if counts["not_checked"] == len(seen):
        raise ValueError(f"None of the {len(seen)} sites could be checked (rate-limited, blocked or changed). "
                         "Try again later.")
    return ParseResult(findings, counts)


MODULE = ModuleSpec(
    number="26",
    id="phoneregistration",
    name=NAME,
    icon="phone",
    description="Whether a number is registered on Instagram, Snapchat or Amazon (ignorant). Active.",
    labels=("external", "active"),
    target_types=(TargetType.PHONE,),
    provider="Instagram, Snapchat and Amazon login and signup forms",
    tools=("ignorant",),
    console_tag=console_tag,
    timeout_s=120,
    active_setting="active.phone_registration",
    notes="Off by default. Needs the Settings switch, a case that allows active lookups, the number in its "
          "authorized scope and a fresh consent.",
)
