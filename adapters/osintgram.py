"""28 Osintgram: one Instagram account's own profile and posts, read through the owner's Instagram login.

Only target-focused commands run (ALLOWED). Follower / following lists and the commands that harvest their
emails or phone numbers are never run: check_allowlist() refuses a manifest that calls anything else.

The login lives in Windows Credential Manager. Right before the run it is written to config/credentials.ini
inside the run folder (Osintgram's working folder); Osintgram removes that folder right after logging in, and
forget_login() deletes it again, with any session or cookie file, when the run ends, whatever the outcome.
"""

from __future__ import annotations

import configparser
import json
import queue
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from adapters._output import unreachable
from core.catalog import load_catalog
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.runner import CommandError, build_command, clean_line, minimal_environment
from core.secrets import INSTAGRAM_LOGIN, parse_login
from core.validation import TargetType

NAME = "Osintgram"
#: Osintgram command -> OsintgramService method. Nothing else may run.
ALLOWED = {
    "info": "get_user_info", "addrs": "get_addrs", "captions": "get_captions", "hashtags": "get_hashtags",
    "mediatype": "get_media_type", "tagged": "get_people_tagged_by_user", "wtagged": "get_people_who_tagged",
    "likes": "get_total_likes", "comments": "get_total_comments",
}
RAW_FILE = "osintgram.jsonl"
NOTE = "From Instagram through your login. A lead, not proof of who runs this account."
MAX_USERS = 25  # tagged / tagged-by accounts stored per run
_SECRET_FILE = re.compile(r"credential|session|cookie|settings\.json", re.I)
_SERVICE_CALL = re.compile(r"\b(?:get|search|compare)_\w+|\b_\w*(?:contact|paginate|iter_items|fetch)\w*")
INFO_LABELS = {
    "full_name": "Name", "biography": "Bio", "follower_count": "Followers", "following_count": "Following",
    "media_count": "Posts", "is_private": "Private account", "is_verified": "Verified",
    "is_business": "Business account", "external_url": "Link in bio", "category": "Category",
    "pronouns": "Pronouns", "public_email": "Public email (on the profile)",
    "contact_phone_number": "Public phone (on the profile)", "city_name": "City", "id": "Instagram ID",
}


# ---------------------------------------------------------------- safety


def check_allowlist(tool) -> None:
    """The manifest code may call only ALLOWED methods, in ALLOWED's command names. Never followers/followings."""
    code = " ".join(tool.launch.args)
    called = set(_SERVICE_CALL.findall(code))
    pairs = dict(re.findall(r'\("(\w+)",\s*"(\w+)"\)', code))
    if "follow" in code.lower() or not called <= set(ALLOWED.values()) or not set(pairs.items()) <= set(ALLOWED.items()):
        raise ValueError("tools/osintgram.yaml asks for commands outside the allowlist; the run was refused.")


def write_login(work_dir: Path, username: str, password: str) -> None:
    config = work_dir / "config"
    config.mkdir(parents=True, exist_ok=True)
    ini = configparser.ConfigParser(interpolation=None)
    ini["Credentials"] = {"username": username, "password": password}
    with open(config / "credentials.ini", "w", encoding="utf-8", newline="\n") as handle:
        ini.write(handle)
    # Osintgram only uses the instagrapi backend when a session file exists; an empty one makes it log in.
    (config / "instagrapi_session.json").write_bytes(b"{}")


def forget_login(work_dir: Path) -> None:
    """Delete the login and any session / cookie / settings file under the run folder. Raises if one stays."""
    for _ in range(10):  # a just-killed process can hold a file for a moment
        shutil.rmtree(work_dir / "config", ignore_errors=True)
        left = [p for p in work_dir.rglob("*") if p.is_file() and _SECRET_FILE.search(p.name)]
        for path in left:
            path.unlink(missing_ok=True)
        if not (work_dir / "config").exists() and not any(p.exists() for p in left):
            return
        time.sleep(0.2)
    raise ValueError(f"Could not delete the Instagram login files in {work_dir}. Delete that folder's config "
                     "files by hand.")


def _kill(process: subprocess.Popen) -> None:
    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False,
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    process.kill()
    process.wait()


def run_process(ctx, program: str, args: list[str], max_bytes: int) -> tuple[int, list[str]]:
    """Argument list, no shell, minimal environment, run folder as cwd. Stops on cancel / timeout / size."""
    process = subprocess.Popen([program, *args], cwd=ctx.work_dir, env=minimal_environment(),
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    pipe: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: [*map(pipe.put, process.stdout), pipe.put(None)], daemon=True).start()
    lines, size = [], 0
    try:
        while True:
            try:
                raw = pipe.get(timeout=0.2)
            except queue.Empty:
                ctx.check()  # the job's timeout or Stop sets this
                continue
            if raw is None:
                return process.wait(), lines
            size += len(raw)
            if size > max_bytes:
                raise ValueError(f"Output exceeded the {max_bytes // 1024} KB limit; the run was stopped.")
            text = clean_line(raw.decode("utf-8", errors="replace"))
            if text.strip():
                lines.append(text)
    finally:
        if process.poll() is None:
            _kill(process)


# ---------------------------------------------------------------- parsing


def _show(value) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def login_problem(error: str) -> str:
    hint = (" Instagram asked for a verification step (2FA or a security check): sign in once with this account "
            "in the Instagram app or a browser, then try again."
            if re.search(r"challenge|checkpoint|two.?factor|verif|EOF", error, re.I) else "")
    return f"Instagram login with your account failed: {error[:300]}{hint}"


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    records = []
    for line in lines:
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and (record.get("command") in ALLOWED or record.get("command") == "login"):
                records.append(record)
    login = next((r for r in records if r["command"] == "login"), None)
    if login:
        raise ValueError(login_problem(str(login.get("error"))))
    if not records:
        raise ValueError((lines[-1][:300] if lines else "") or "Osintgram printed no results.")
    errors = [r for r in records if "error" in r]
    if len(errors) == len(records):
        raise ValueError(f"Osintgram could not read @{target}: {str(errors[0]['error'])[:300]}")

    findings: list[Finding] = []
    counts = {"commands": len(records) - len(errors), "failed_commands": len(errors)}
    source = "Osintgram (your Instagram login)"
    profile = f"https://www.instagram.com/{target}/"

    def add(title, value, result=ResultKind.INFO, url=None, notes="", confidence=Confidence.MEDIUM):
        findings.append(Finding(module=NAME, title=title, value=_show(value)[:4000], url=url, source=source,
                                confidence=confidence, result=result, raw_ref=RAW_FILE, notes=notes))

    for record in records:
        command, data = record["command"], record.get("data")
        if "error" in record:
            findings.append(unreachable(NAME, f"Osintgram {command}", str(record["error"])[:300]))
        elif command == "info" and isinstance(data, dict):
            add("Instagram profile", profile, ResultKind.FOUND, profile, NOTE)
            for key, value in data.items():
                if value in (None, "", [], {}) or key in ("username", "bio_links", "profile_pic_url_hd"):
                    continue
                add(f"Instagram: {INFO_LABELS.get(key, key.replace('_', ' '))}", value)
            for link in data.get("bio_links") or []:
                add("Instagram: Bio link", link.get("url"), url=link.get("url"), notes=link.get("title") or "")
            if data.get("profile_pic_url_hd"):
                add("Instagram: Profile picture", data["profile_pic_url_hd"], url=data["profile_pic_url_hd"])
        elif command == "addrs" and isinstance(data, list):
            for place in data:
                add(f"Geotagged place: {place.get('name') or place.get('address')}", place.get("address"),
                    ResultKind.FOUND, notes=f"Post from {place.get('time')} at {place.get('lat')}, {place.get('lng')}. "
                    "Where a post was tagged, not proof of where anyone was.", confidence=Confidence.LOW)
            counts["places"] = len(data)
        elif command == "captions" and isinstance(data, list) and data:
            add(f"Captions ({len(data)} recent posts)", "\n---\n".join(map(str, data)), notes=f"All in {RAW_FILE}.")
        elif command == "hashtags" and isinstance(data, list) and data:
            add("Hashtags used", ", ".join(f"{h.get('hashtag')} ({h.get('count')})" for h in data[:50]))
        elif command == "mediatype" and isinstance(data, dict):
            add("Post types", f"{data.get('photos')} photos, {data.get('videos')} videos, "
                              f"{data.get('carousels')} carousels in {data.get('total')} recent posts")
        elif command in ("tagged", "wtagged") and isinstance(data, list):
            for user in data[:MAX_USERS]:
                name = user.get("username")
                if not name:
                    continue
                times = user.get("posts") or user.get("counter")
                add(f"Tagged by @{target}: @{name}" if command == "tagged" else f"Tagged @{target}: @{name}",
                    f"@{name}" + (f" ({user['full_name']})" if user.get("full_name") else ""), ResultKind.FOUND,
                    f"https://www.instagram.com/{name}/", f"{times} post(s). A connection lead, not proof of a "
                    "relationship.", Confidence.LOW)
            counts[command] = len(data)
        elif command in ("likes", "comments") and isinstance(data, dict):
            total = data.get("like_counter" if command == "likes" else "comment_counter")
            add(f"{command.capitalize()} on recent posts", f"{total} in {data.get('posts')} posts "
                f"(avg {data.get('avg')}, min {data.get('min')}, max {data.get('max')})")
    return ParseResult(findings, counts)


# ---------------------------------------------------------------- run


def run(ctx) -> list[Finding]:
    login = parse_login(ctx.api_key)
    if login is None:
        raise ValueError("Add your Instagram account in Settings → API keys first.")
    tool = load_catalog().get("osintgram")
    if tool is None:
        raise ValueError("tools/osintgram.yaml is missing or invalid (see Tool Library).")
    check_allowlist(tool)
    try:
        program, args = build_command(tool, TargetType.USERNAME, ctx.target, ctx.work_dir)
    except CommandError as exc:
        raise ValueError(str(exc)) from None
    for old in ctx.work_dir.parent.glob("*/config"):  # left behind if the app was killed mid-run
        forget_login(old.parent)
    username, password = login
    ctx.emit(f"[i] logging in to Instagram as @{username} (your account), then reading @{ctx.target}")
    try:
        write_login(ctx.work_dir, username, password)
        code, lines = run_process(ctx, program, args, tool.launch.max_output_kb * 1024)
    finally:
        forget_login(ctx.work_dir)
    if len(password) >= 4:  # in case a library echoes it (a shorter one would garble ordinary text)
        lines = [line.replace(password, "[password]") for line in lines]
    with open(ctx.work_dir / RAW_FILE, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    for line in lines:
        if not line.startswith("{"):
            ctx.emit(line)
    result = parse(lines, ctx.work_dir, ctx.target)
    for finding in result.findings:
        ctx.emit(f"[+] {finding.title}: {(finding.value or '')[:200]}")
    if code not in (0, None) and not result.findings:
        raise ValueError(f"Osintgram exited with code {code}.")
    return result.findings


MODULE = ModuleSpec(
    number="28",
    id="osintgram",
    name=NAME,
    icon="user",
    description="Profile, captions, hashtags, geotagged places, post types, tags, likes and comments of one "
                "account, through your own Instagram login.",
    labels=("external", "passive", "api_key"),
    target_types=(TargetType.USERNAME,),
    provider="Instagram, logged in as YOUR Instagram account (Instagram may block or ban it), and OpenStreetMap "
             "Nominatim (coordinates of geotagged posts)",
    run=run,
    timeout_s=600,
    max_output_kb=2048,
    api_key=INSTAGRAM_LOGIN.name,
    api_key_required=True,
    needs_tool="osintgram",
    engine_name="Osintgram (your login)",
    notes="Uses your own Instagram login (Settings → API keys); use a secondary account. Never collects "
          "follower or following lists or their contact details.",
)
