"""07 SubdomainScan: known subdomains from certificate transparency logs (crt.sh)."""

from __future__ import annotations

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType, ValidationError, validate_target

NAME = "SubdomainScan"
MAX_NAMES = 500


def names_from_crtsh(rows: list[dict], domain: str) -> list[str]:
    names = set()
    for row in rows or []:
        for raw in str(row.get("name_value", "")).splitlines():
            name = raw.strip().lower().removeprefix("*.")
            if name == domain or not name.endswith("." + domain):
                continue
            try:
                names.add(validate_target(TargetType.DOMAIN, name))
            except ValidationError:
                continue
    return sorted(names)


@unexpected_output("crt.sh")
def run(ctx) -> list[Finding]:
    ctx.emit(f"[i] crt.sh certificate search for %.{ctx.target} (can be slow)")
    rows = ctx.http().get_json("crt.sh", "https://crt.sh/", params={"q": f"%.{ctx.target}", "output": "json"},
                               timeout=90)
    names = names_from_crtsh(rows, ctx.target)
    ctx.emit(f"[i] {len(rows or [])} certificates, {len(names)} unique subdomains")
    findings = []
    for name in names[:MAX_NAMES]:
        ctx.emit(f"[+] {name}")
        findings.append(Finding(module=NAME, title=f"Subdomain {name}", value=name, source="crt.sh",
                                confidence=Confidence.MEDIUM, result=ResultKind.FOUND,
                                notes="Seen in a logged certificate. It may no longer exist or resolve."))
    if len(names) > MAX_NAMES:
        ctx.emit(f"[!] showing the first {MAX_NAMES} of {len(names)}")
    return findings


MODULE = ModuleSpec(
    number="07",
    id="subdomainscan",
    name=NAME,
    icon="tree",
    description="Known subdomains from certificate logs and passive sources.",
    labels=("external", "passive"),
    target_types=(TargetType.DOMAIN,),
    provider="crt.sh (certificate transparency search)",
    run=run,
    engine_name="crt.sh (built-in)",
    tools=("subfinder", "theharvester", "spiderfoot"),
    console_tag=lambda line: "g" if line.startswith("[+]") else ("y" if line.startswith("[!]") else "p"),
    timeout_s=150,
    max_output_kb=2048,
)
