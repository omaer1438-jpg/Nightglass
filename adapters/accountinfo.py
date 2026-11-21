"""16 AccountInfo: public profile summary from pages that need no login (Instagram, Threads, Telegram).

Reads only what any visitor sees. A site that asks for a login or shows a bot check is reported and skipped.
"""

from __future__ import annotations

import html
import re

from adapters._output import unreachable
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.net import NetError
from core.validation import TargetType

NAME = "AccountInfo"
NOTE = "Username match only. Not proof that the target owns this account."
#: site, profile URL, text that only a real profile page has, and the og: field or raw page it is searched in
SITES = (
    ("Instagram", "https://www.instagram.com/{}/", " Followers", "description"),
    ("Threads", "https://www.threads.com/@{}", " Followers", "description"),
    ("Telegram", "https://t.me/{}", "tgme_page_title", None),
)


def meta(page: str, field: str) -> str:
    match = re.search(rf'<meta[^>]+property="og:{field}"[^>]+content="([^"]*)"', page)
    return html.unescape(match[1]).strip() if match else ""


def profile(page: str, marker: str, field: str | None) -> tuple[str, str] | None:
    """(display name, public summary), or None when this is not a real profile page."""
    if marker not in (meta(page, field) if field else page):
        return None
    return meta(page, "title"), meta(page, "description")


def run(ctx) -> list[Finding]:
    findings: list[Finding] = []
    failed: list[str] = []
    for site, template, marker, field in SITES:
        url = template.format(ctx.target)
        ctx.emit(f"[i] GET {url}")
        try:
            response = ctx.http().request(site, url, ok_statuses=(200, 404))
        except NetError as exc:
            ctx.emit(f"[?] {exc}")
            failed.append(str(exc))
            findings.append(unreachable(NAME, site, str(exc)))
            continue
        found = profile(response.text, marker, field) if response.status == 200 else None
        if found is None:
            ctx.emit(f"[-] {site}: no public profile to read (not found, or it needs a login)")
            continue
        title, summary = found
        ctx.emit(f"[+] {site} profile: {url}")
        findings.append(Finding(module=NAME, title=f"{site} profile", value=url, url=url, source=site,
                                confidence=Confidence.MEDIUM, result=ResultKind.FOUND, notes=NOTE))
        for label, value in (("name", title), ("public summary", summary)):
            if value:
                ctx.emit(f"[+] {site} {label}: {value}")
                findings.append(Finding(module=NAME, title=f"{site}: {label}", value=value[:4000], source=site,
                                        confidence=Confidence.MEDIUM, result=ResultKind.INFO))
    if len(failed) == len(SITES):
        raise NetError("No site could be checked. " + " ".join(failed))
    return findings


MODULE = ModuleSpec(
    number="16",
    id="accountinfo",
    name=NAME,
    icon="user",
    description="Public name, followers and posts from Instagram, Threads and Telegram profile pages.",
    labels=("external", "passive"),
    target_types=(TargetType.USERNAME,),
    provider="Instagram, Threads and Telegram (their public profile pages)",
    run=run,
    timeout_s=60,
    notes="Those sites don't show a creation date publicly. For dates, run UserRecon with Maigret.",
)
