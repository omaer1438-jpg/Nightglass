"""Maigret parser (engine of 01 UserRecon).

Maigret writes report_<username>_simple.json into the run folder (-J simple --folderoutput):
{site_name: {"url_user": ..., "status": {"status": "Claimed", "ids": {...}, ...}, ...}}
Only claimed accounts are in the file. Console lines "[+] Site: url" are the fallback.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ParseResult

MODULE_NAME = "UserRecon"
_FOUND = re.compile(r"^\[\+\]\s+(?P<site>[^:]+?):\s*(?P<url>https?://\S+)")
NOTE = "Username match only. Not proof that the target owns this account."
FACTS = {"created_at": "account created", "latest_activity_at": "last activity", "fullname": "name",
         "follower_count": "followers", "following_count": "following", "posts_count": "posts"}


def _finding(site: str, url: str | None, extra: str = "") -> Finding:
    notes = NOTE + (f" Extracted: {extra}" if extra else "")
    return Finding(module=MODULE_NAME, title=f"{site} profile", value=url or site, url=url, source="Maigret",
                   confidence=Confidence.MEDIUM, result=ResultKind.FOUND, raw_ref="report json",
                   notes=notes[:4000])


@unexpected_output("Maigret")
def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    findings: list[Finding] = []
    facts = 0
    report = Path(work_dir) / f"report_{target}_simple.json" if work_dir and target else None
    if report is not None and report.is_file():
        data = json.loads(report.read_text(encoding="utf-8") or "{}")
        for site, entry in sorted(data.items()):
            status = entry.get("status") or {}
            url = entry.get("url_user") or status.get("url")
            if url and not str(url).startswith(("http://", "https://")):
                url = None
            ids = status.get("ids") or {}
            extra = ", ".join(f"{k}: {v}" for k, v in list(ids.items())[:8])
            findings.append(_finding(site, url, extra))
            for key, title in FACTS.items():
                if ids.get(key) not in (None, ""):
                    facts += 1
                    findings.append(Finding(module=MODULE_NAME, title=f"{site}: {title}", value=str(ids[key])[:4000],
                                            source="Maigret", confidence=Confidence.MEDIUM, result=ResultKind.INFO,
                                            raw_ref="report json"))
    else:
        seen = set()
        for line in lines:
            match = _FOUND.match(line.strip())
            if match and match["site"] not in seen:
                seen.add(match["site"])
                findings.append(_finding(match["site"].strip(), match["url"]))
    return ParseResult(findings, {"found": len(findings) - facts, "account_facts": facts})
