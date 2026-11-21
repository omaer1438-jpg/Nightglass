"""17 TikTokPage: reads a TikTok profile page you saved from your own browser. Nothing is sent anywhere.

TikTok answers automated requests with a bot check, and Nightglass does not get around it. Open the profile
in your browser, press Ctrl+S ("Webpage, HTML only") and choose that file here.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "TikTokPage"
NOTE = "Taken from a saved public page. Not proof of who runs this account."
ESTIMATE = "Estimated from the account ID (accurate to a few minutes)."
HOW_TO = "Open the profile in your browser, press Ctrl+S (Webpage, HTML only), then choose that file."
MAX_BYTES = 30 * 1024 * 1024
_DATA = re.compile(r'<script[^>]+id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', re.S)
#: Shown first, in this order. Any other field the page holds follows under its own name.
LABELS = {
    "id": "ID", "uniqueId": "Username", "nickname": "Name", "signature": "Bio",
    "followerCount": "Followers", "followingCount": "Following", "friendCount": "Friends",
    "heartCount": "Likes", "videoCount": "Videos", "createTime": "Created",
    "uniqueIdModifyTime": "Username changed", "nickNameModifyTime": "Name changed",
    "region": "Country", "language": "Language", "verified": "Verified", "privateAccount": "Private account",
    "secret": "Secret account", "ttSeller": "TikTok seller", "commerceUser": "Has shop",
    "isOrganization": "Organization account", "followingVisibility": "Following list visibility",
    "downloadSetting": "Download setting", "duetSetting": "Duet setting", "stitchSetting": "Stitch setting",
    "commentSetting": "Comment setting", "relation": "Relation", "openFavorite": "Favorites public",
    "isEmbedBanned": "Embedding banned", "showMusicTab": "Music tab", "showQuestionTab": "Question tab",
    "showPlayListTab": "Playlist tab", "suggestAccountBind": "Suggests account link",
    "canExpPlaylist": "Expandable playlists", "profileEmbedPermission": "Embed permission",
    "ftc": "FTC compliant", "isADVirtual": "Virtual ad account",
}
SKIPPED = ("avatar", "secUid", "heart")  # image links and duplicates of the fields above


def read_profile(page: str) -> dict:
    """userInfo.user and userInfo.stats merged into one flat dict."""
    match = _DATA.search(page)
    try:
        info = json.loads(match[1])["__DEFAULT_SCOPE__"]["webapp.user-detail"]["userInfo"]
    except (TypeError, ValueError, KeyError):
        raise ValueError(f"This file isn't a saved TikTok profile page. {HOW_TO}") from None
    fields: dict = {}
    for key, value in {**info.get("user", {}), **info.get("stats", {})}.items():
        if isinstance(value, dict):
            fields.update(value)
        else:
            fields[key] = value
    return fields


def created_from_id(user_id) -> str:
    """TikTok IDs start with the second they were made."""
    return _time(int(user_id) >> 32)


def _time(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if value else "Never"


def _show(key: str, value) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if key.endswith("Time") and isinstance(value, int):
        return _time(value)
    return str(value)


def rows(fields: dict) -> list[tuple[str, str, str]]:
    """(label, value, note) for every field, the known ones first."""
    known = [key for key in LABELS if key in fields]
    others = sorted(k for k in fields if k not in LABELS and not k.startswith(SKIPPED)
                    and not isinstance(fields[k], list))
    result = []
    for key in known + others:
        value, note = _show(key, fields[key]), ""
        if key == "createTime" and not fields[key] and fields.get("id"):
            value, note = created_from_id(fields["id"]), ESTIMATE
        result.append((LABELS.get(key, key), value or "(empty)", note))
    if "createTime" not in fields and fields.get("id"):
        result.insert(4, ("Created", created_from_id(fields["id"]), ESTIMATE))
    return result


def run(ctx) -> list[Finding]:
    path = Path(ctx.target)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("This file is too large to be a saved profile page.")
    fields = read_profile(path.read_text(encoding="utf-8", errors="replace"))
    username = fields.get("uniqueId")
    url = f"https://www.tiktok.com/@{username}"
    ctx.emit(f"[+] TikTok profile: {url}")
    findings = [Finding(module=NAME, title="TikTok profile", value=url, url=url, source="Saved TikTok page",
                        confidence=Confidence.MEDIUM, result=ResultKind.FOUND, notes=NOTE)]
    for title, value, note in rows(fields):
        ctx.emit(f"[+] {title}: {value}")
        findings.append(Finding(module=NAME, title=f"TikTok: {title}", value=value[:4000], source="Saved TikTok page",
                                confidence=Confidence.MEDIUM, result=ResultKind.INFO, notes=note))
    return findings


MODULE = ModuleSpec(
    number="17",
    id="tiktokpage",
    name=NAME,
    icon="user",
    description="Every account detail in a TikTok profile page you saved from your browser.",
    labels=("local",),
    target_types=(TargetType.FILE,),
    provider="None: it reads a file on this computer",
    run=run,
    timeout_s=30,
    notes=HOW_TO,
)
