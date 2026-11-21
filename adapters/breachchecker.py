"""12 BreachChecker: breaches an e-mail appears in (Have I Been Pwned API v3, key required).

Never stores or displays passwords: only breach names, dates and the kinds of data exposed.
"""

from __future__ import annotations

from urllib.parse import quote

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "BreachChecker"


@unexpected_output("Have I Been Pwned")
def run(ctx) -> list[Finding]:
    if not ctx.api_key:
        raise ValueError("Add the Have I Been Pwned API key in Settings first.")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(ctx.target, safe='@')}"
    ctx.emit(f"[i] Have I Been Pwned lookup for {ctx.target}")
    breaches = ctx.http().get_json("hibp", url, params={"truncateResponse": "false"},
                                   headers={"hibp-api-key": ctx.api_key}, ok_statuses=(200, 404))
    if not breaches:
        ctx.emit("[-] not found in any breach known to HIBP")
        return [Finding(module=NAME, title="No known breaches", value=ctx.target, source="Have I Been Pwned",
                        confidence=Confidence.HIGH, result=ResultKind.INFO,
                        notes="Only breaches HIBP has loaded. Absence doesn't prove the address was never exposed.")]
    findings = []
    for breach in breaches:
        classes = ", ".join(breach.get("DataClasses") or [])
        date = breach.get("BreachDate") or ""
        ctx.emit(f"[+] {breach.get('Title') or breach.get('Name')} ({date})")
        findings.append(Finding(
            module=NAME, title=f"Breach: {breach.get('Title') or breach.get('Name')}",
            value=f"{date} · {classes}"[:4000], source="Have I Been Pwned",
            url=f"https://haveibeenpwned.com/PwnedWebsites#{quote(str(breach.get('Name', '')))}",
            confidence=Confidence.HIGH, result=ResultKind.FOUND,
            notes="Exposure record for this address. Passwords are never fetched or stored.",
        ))
    return findings


MODULE = ModuleSpec(
    number="12",
    id="breachchecker",
    name=NAME,
    icon="shield",
    description="Breaches an email appears in, via Have I Been Pwned.",
    labels=("external", "api_key"),
    target_types=(TargetType.EMAIL,),
    provider="Have I Been Pwned (haveibeenpwned.com)",
    run=run,
    api_key="haveibeenpwned",
    api_key_required=True,
    timeout_s=60,
)
