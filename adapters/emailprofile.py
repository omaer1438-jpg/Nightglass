"""23 EmailProfile: what is public about an address: its Gravatar profile, mail setup and disposable-domain status.

Gravatar receives a hash of the address and Kickbox only the domain, so the address itself is not sent to either.
"""

from __future__ import annotations

import hashlib

import dns.exception

from adapters._output import unexpected_output, unreachable
from adapters.dnsrecon import query, resolver
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.net import NetError
from core.validation import TargetType

NAME = "EmailProfile"
NOTE = "Public profile tied to this address. Not proof of who is behind it."
GRAVATAR = {"displayName": "Name", "preferredUsername": "Username", "aboutMe": "About", "currentLocation": "Location",
            "company": "Company", "job_title": "Job title"}


def gravatar_url(address: str) -> str:
    return f"https://gravatar.com/{hashlib.sha256(address.strip().lower().encode()).hexdigest()}.json"


@unexpected_output("Gravatar or Kickbox")
def run(ctx) -> list[Finding]:
    domain = ctx.target.rpartition("@")[2]
    findings: list[Finding] = []

    def add(title, value, source, result=ResultKind.INFO, url=None, notes=""):
        ctx.emit(f"[+] {title}: {value}")
        findings.append(Finding(module=NAME, title=title, value=str(value)[:4000], url=url, source=source,
                                confidence=Confidence.MEDIUM, result=result, notes=notes))

    failed: list[str] = []

    def not_checked(source, reason):
        ctx.emit(f"[?] {reason}")
        failed.append(reason)
        findings.append(unreachable(NAME, source, reason))

    http = ctx.http()
    ctx.emit("[i] Gravatar lookup (hash of the address)")
    try:
        data = http.get_json("gravatar", gravatar_url(ctx.target), ok_statuses=(200, 404))
    except NetError as exc:
        not_checked("Gravatar", str(exc))
        data = None
    if data and data.get("entry"):
        entry = data["entry"][0]
        add("Gravatar profile", entry.get("profileUrl"), "Gravatar", ResultKind.FOUND, entry.get("profileUrl"), NOTE)
        for key, title in GRAVATAR.items():
            if entry.get(key):
                add(f"Gravatar: {title}", entry[key], "Gravatar")
        for account in entry.get("accounts") or []:
            if account.get("url"):
                name = account.get("shortname") or account.get("name") or "account"
                add(f"Linked account: {name}", account["url"], "Gravatar", ResultKind.FOUND, account["url"], NOTE)
    elif not failed:
        ctx.emit("[-] no public Gravatar profile")

    ctx.emit(f"[i] mail setup of {domain}")
    lookup = resolver()
    dns_errors = []
    for title, name, rtype, marker in (("Mail servers (MX)", domain, "MX", ""), ("SPF record", domain, "TXT", "v=spf1"),
                                       ("DMARC record", f"_dmarc.{domain}", "TXT", "v=DMARC1")):
        ctx.check()
        try:
            records = [r for r in query(lookup, name, rtype) if marker in r]
        except dns.exception.DNSException as exc:
            ctx.emit(f"[?] {title}: {type(exc).__name__}")
            dns_errors.append(f"{rtype} {name}: {type(exc).__name__}")
            continue
        add(title, "; ".join(records) or "None", "DNS")
    if len(dns_errors) == 3:
        not_checked("DNS", "No DNS answer for the mail setup (" + "; ".join(dns_errors) + ").")

    try:
        disposable = http.get_json("kickbox", f"https://open.kickbox.com/v1/disposable/{domain}") or {}
    except NetError as exc:
        not_checked("Kickbox", str(exc))
    else:
        if "disposable" in disposable:
            add("Disposable mail domain", "Yes" if disposable["disposable"] else "No", "Kickbox")
    if len(failed) == 3:  # Gravatar, DNS and Kickbox: nothing could be checked
        raise NetError("Nothing could be checked. " + " ".join(failed))
    return findings


MODULE = ModuleSpec(
    number="23",
    id="emailprofile",
    name=NAME,
    icon="mail",
    description="Public Gravatar profile, linked accounts, mail setup and disposable-domain check.",
    labels=("external", "passive"),
    target_types=(TargetType.EMAIL,),
    provider="Gravatar (a hash of the address), Kickbox (the domain only) and your DNS resolver",
    run=run,
    timeout_s=45,
)
