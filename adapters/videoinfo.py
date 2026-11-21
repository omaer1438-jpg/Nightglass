"""21 VideoInfo: public details of a video (yt-dlp). Nothing is downloaded but its info file.

yt-dlp writes video.info.json into the run folder (--write-info-json -o video).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.validation import TargetType

NAME = "VideoInfo"
NOTE = "As published by the site. The uploader's name is not proof of identity."
FIELDS = {"title": "Title", "uploader": "Uploader", "uploader_id": "Uploader ID", "channel": "Channel",
          "channel_id": "Channel ID", "duration": "Duration (s)", "view_count": "Views", "like_count": "Likes",
          "comment_count": "Comments", "age_limit": "Age limit", "description": "Description"}


def _uploaded(info: dict) -> str | None:
    if info.get("timestamp"):
        return datetime.fromtimestamp(info["timestamp"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    day = str(info.get("upload_date") or "")
    return f"{day[:4]}-{day[4:6]}-{day[6:8]}" if len(day) == 8 else None


@unexpected_output("yt-dlp")
def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    report = Path(work_dir) / "video.info.json" if work_dir else None
    if report is None or not report.is_file():
        error = next((line.strip() for line in reversed(lines) if line.lstrip().upper().startswith("ERROR")), "")
        raise ValueError(error[:300] or "yt-dlp wrote no video details.")
    info = json.loads(report.read_text(encoding="utf-8"))
    url = info.get("webpage_url") or target
    site = str(info.get("extractor") or "video site")
    findings = [Finding(module=NAME, title="Video", value=url, url=url, source=site, confidence=Confidence.HIGH,
                        result=ResultKind.FOUND, raw_ref="video.info.json", notes=NOTE)]
    rows = [("Uploaded", _uploaded(info))] + [(title, info.get(key)) for key, title in FIELDS.items()]
    for title, value in rows:
        if value not in (None, ""):
            findings.append(Finding(module=NAME, title=title, value=str(value)[:4000], source=site,
                                    confidence=Confidence.HIGH, result=ResultKind.INFO, raw_ref="video.info.json"))
    return ParseResult(findings, {"found": 1, "fields": len(findings) - 1})


MODULE = ModuleSpec(
    number="21",
    id="videoinfo",
    name=NAME,
    icon="play",
    description="Upload date, uploader, views and likes of a public video from its URL.",
    labels=("external", "passive", "oss"),
    target_types=(TargetType.URL,),
    provider="The video site in the URL",
    tools=("yt_dlp",),
    timeout_s=120,
    max_output_kb=1024,
    notes="Reads public pages only: no account, no cookies, no video download.",
)
