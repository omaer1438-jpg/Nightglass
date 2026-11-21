"""02 EmailFootprint: Blackbird email output parser.

Blackbird prints one line per account it finds (rich console, no colour when piped):
    ✔️  [GitHub] https://github.com/example_user
Not-found sites are only printed with --verbose, which is not passed.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.validation import TargetType

NAME = "EmailFootprint"
_FOUND = re.compile(r"^\s*✔️?\s*\[(?P<site>[^\]]+)\](?:\s+(?P<url>https?://\S+))?\s*$")
_DONE = re.compile(r"\((?P<sites>\d+) sites\)")


def console_tag(line: str) -> str:
    if _FOUND.match(line):
        return "g"
    if "❌" in line or "⛔" in line:
        return "b"
    return "p"


def accounts(lines: list[str]) -> list[tuple[str, str]]:
    """(site, url) pairs. On a narrow console rich wraps a hit: the URL moves to the next line and a long
    URL is cut into pieces, each on its own unindented line with no spaces. Those pieces are joined."""
    found: list[list[str]] = []
    joining = False  # the last line belonged to the latest hit's URL
    for line in lines:
        match = _FOUND.match(line)
        if match:
            found.append([match["site"], match["url"] or ""])
            joining = True
        elif joining and line.strip() and line == line.lstrip() and " " not in line.strip() \
                and (not found[-1][1]) == line.startswith(("http://", "https://")):  # start of the URL, or a piece of it
            found[-1][1] += line.strip()
        else:
            joining = False
    return [(site, url) for site, url in found if url]


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    findings, seen, checked = [], set(), 0
    for site, url in accounts(lines):
        if site not in seen:
            seen.add(site)
            findings.append(Finding(
                module=NAME, title=f"{site} account", value=url, url=url,
                source="Blackbird", confidence=Confidence.MEDIUM, result=ResultKind.FOUND, raw_ref="run.log",
                notes="The site reports an account for this email. Not proof of who controls it.",
            ))
    for line in lines:
        done = _DONE.search(line)
        if done:
            checked = int(done["sites"])
    counts = {"found": len(findings)}
    if checked:
        counts["checked"] = checked
    return ParseResult(findings, counts)


def parse_username(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    """The same console output, as an engine of 01 UserRecon."""
    result = parse(lines, work_dir, target)
    note = "Username match only. Not proof that the target owns this account."
    return ParseResult([f.model_copy(update={"module": "UserRecon", "notes": note}) for f in result.findings], result.counts)


MODULE = ModuleSpec(
    number="02",
    id="emailfootprint",
    name=NAME,
    icon="mail",
    description="Platforms where an email appears to be registered.",
    labels=("external", "passive"),
    target_types=(TargetType.EMAIL,),
    provider="Sites in Blackbird's bundled email list (account-exists checks)",
    tools=("blackbird", "holehe"),  # Holehe is the active add-on: its own gates and consent apply
    console_tag=console_tag,
    timeout_s=300,
    max_output_kb=4096,
    notes="Holehe (active) stays a separate, opt-in tool.",
)
