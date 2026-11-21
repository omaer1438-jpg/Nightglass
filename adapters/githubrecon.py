"""11 GitHubRecon: public profile, repositories and public activity (GitHub REST API).

Never looks for, uses or tests secrets. Commit e-mail addresses are not collected.
"""

from __future__ import annotations

from collections import Counter

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "GitHubRecon"
API = "https://api.github.com"


@unexpected_output("GitHub")
def run(ctx) -> list[Finding]:
    http = ctx.http()
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"
    ctx.emit(f"[i] GET {API}/users/{ctx.target}")
    user = http.get_json("github", f"{API}/users/{ctx.target}", headers=headers, ok_statuses=(200, 404))
    if not user:
        ctx.emit("[-] no GitHub account with this username")
        return [Finding(module=NAME, title="No GitHub account", value=ctx.target, source="GitHub API",
                        confidence=Confidence.HIGH, result=ResultKind.INFO,
                        notes="No account by this exact name. Other spellings may exist.")]
    findings: list[Finding] = []
    profile_url = user.get("html_url")
    findings.append(Finding(module=NAME, title="GitHub profile", value=profile_url, url=profile_url,
                            source="GitHub API", confidence=Confidence.HIGH, result=ResultKind.FOUND,
                            notes="Same username, not proof of identity."))
    ctx.emit(f"[+] profile {profile_url}")
    for key, title in (("name", "Display name"), ("company", "Company"), ("blog", "Website"),
                       ("location", "Location (self-reported)"), ("bio", "Bio"), ("public_repos", "Public repositories"),
                       ("followers", "Followers"), ("created_at", "Account created")):
        value = user.get(key)
        if value not in (None, "", 0) or key in ("public_repos", "followers"):
            ctx.emit(f"[+] {title}: {value}")
            findings.append(Finding(module=NAME, title=title, value=str(value)[:4000], source="GitHub API",
                                    confidence=Confidence.HIGH, result=ResultKind.INFO))
    ctx.check()
    repos = http.get_json("github", f"{API}/users/{ctx.target}/repos", headers=headers,
                          params={"sort": "updated", "per_page": 10}) or []
    for repo in repos:
        if repo.get("fork"):
            continue
        description = (repo.get("description") or "").strip()
        value = f"{description} · updated {str(repo.get('pushed_at') or '')[:10]}".strip(" ·")
        ctx.emit(f"[+] repo {repo.get('full_name')}")
        findings.append(Finding(module=NAME, title=f"Repository {repo.get('name')}", value=value or None,
                                url=repo.get("html_url"), source="GitHub API", confidence=Confidence.HIGH,
                                result=ResultKind.INFO))
    ctx.check()
    events = http.get_json("github", f"{API}/users/{ctx.target}/events/public", headers=headers,
                           params={"per_page": 30}) or []
    if events:
        kinds = Counter(e.get("type", "?").removesuffix("Event") for e in events)
        latest = str(events[0].get("created_at") or "")[:10]
        summary = ", ".join(f"{n} {k}" for k, n in kinds.most_common(5))
        ctx.emit(f"[+] recent public activity: {summary} (latest {latest})")
        findings.append(Finding(module=NAME, title="Recent public activity", value=f"{summary} · latest {latest}",
                                source="GitHub API", confidence=Confidence.HIGH, result=ResultKind.INFO))
    return findings


MODULE = ModuleSpec(
    number="11",
    id="githubrecon",
    name=NAME,
    icon="git",
    description="Public profile, repositories and public activity.",
    labels=("external", "passive", "api_key"),
    target_types=(TargetType.USERNAME,),
    provider="GitHub REST API (api.github.com)",
    run=run,
    api_key="github",
    timeout_s=60,
    notes="Token optional (raises the rate limit). Never use or test exposed secrets.",
)
