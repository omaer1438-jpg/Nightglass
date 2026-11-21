"""27 InstagramPage: what a public Instagram profile page shows without a login.

Reads the page's own meta tags (name, bio, follower / following / post counts, picture). No login, no API.
"""

from __future__ import annotations

import html
import re

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.net import NetError
from core.validation import TargetType

NAME = "InstagramPage"
NOTE = "Public profile page. Not proof of who runs this account."
LOGIN_WALL = ("Instagram asked for a login; try Osintgram with your account or open the profile in a browser.")
_META = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(r'([a-z][a-z:_-]*)\s*=\s*"([^"]*)"', re.I)
_COUNTS = re.compile(r"([\d.,]+[KMB]?) Followers?, ([\d.,]+[KMB]?) Following, ([\d.,]+[KMB]?) Posts?", re.I)
_BIO = re.compile(r' on Instagram: "(.*)"\s*$', re.S)


def meta_tags(page: str) -> dict[str, str]:
    """{og:title: ..., description: ...} from the page's <meta> tags, entities decoded."""
    tags = {}
    for tag in _META.findall(page):
        attrs = {k.lower(): v for k, v in _ATTR.findall(tag)}
        key = attrs.get("property") or attrs.get("name")
        if key and "content" in attrs:
            tags.setdefault(key.lower(), html.unescape(attrs["content"]))
    return tags


def read_profile(page: str, username: str) -> list[tuple[str, str]]:
    """(label, value) rows, or ValueError when the page isn't a public profile."""
    tags = meta_tags(page)
    counts = _COUNTS.search(tags.get("og:description", "") or tags.get("description", ""))
    if not counts:
        raise ValueError(LOGIN_WALL)
    rows = []
    name = re.match(rf"^(.*?)\s*\(@{re.escape(username)}\)", tags.get("og:title", ""), re.I)
    if name and name[1]:
        rows.append(("Name", name[1]))
    rows += [("Followers", counts[1]), ("Following", counts[2]), ("Posts", counts[3])]
    bio = _BIO.search(tags.get("description", ""))
    if bio and bio[1].strip():
        rows.append(("Bio", bio[1].strip()))
    if tags.get("og:image", "").startswith("https://"):
        rows.append(("Profile picture", tags["og:image"]))
    return rows


def run(ctx) -> list[Finding]:
    username = ctx.target.lstrip("@")
    url = f"https://www.instagram.com/{username}/"
    ctx.emit(f"[i] reading the public page {url}")
    response = ctx.http().request("instagram", url, ok_statuses=(200, 404))
    if response.status == 404:
        raise NetError(f"Instagram has no public profile @{username} (404).")
    if "/accounts/login" in response.url or "/challenge" in response.url:
        raise ValueError(LOGIN_WALL)
    rows = read_profile(response.text, username)
    ctx.emit(f"[+] Instagram profile: {url}")
    findings = [Finding(module=NAME, title="Instagram profile", value=url, url=url, source="Instagram public page",
                        confidence=Confidence.MEDIUM, result=ResultKind.FOUND, notes=NOTE)]
    for title, value in rows:
        ctx.emit(f"[+] {title}: {value}")
        findings.append(Finding(module=NAME, title=f"Instagram: {title}", value=value,
                                url=value if title == "Profile picture" else None, source="Instagram public page",
                                confidence=Confidence.MEDIUM, result=ResultKind.INFO))
    return findings


MODULE = ModuleSpec(
    number="27",
    id="instagrampage",
    name=NAME,
    icon="user",
    description="Name, bio, follower / following / post counts and picture from a public Instagram profile page.",
    labels=("external", "passive"),
    target_types=(TargetType.USERNAME,),
    provider="Instagram (the public profile page, no login)",
    run=run,
    timeout_s=30,
    notes="Instagram often shows a login wall to tools. Then use Osintgram or open the profile in a browser.",
)
