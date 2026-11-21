"""13 ReverseIP: hostnames and indexed open ports for an IP (Shodan InternetDB) plus PTR."""

from __future__ import annotations

from adapters._output import unexpected_output
from adapters.dnsrecon import ptr, resolver
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "ReverseIP"


@unexpected_output("Shodan InternetDB")
def run(ctx) -> list[Finding]:
    findings: list[Finding] = []

    def add(title, value, source, result=ResultKind.INFO, confidence=Confidence.MEDIUM, notes=""):
        ctx.emit(f"[+] {title}: {value}")
        findings.append(Finding(module=NAME, title=title, value=str(value)[:4000], source=source,
                                result=result, confidence=confidence, notes=notes))

    ctx.emit(f"[i] PTR lookup for {ctx.target}")
    for name in ptr(resolver(), ctx.target):
        add("PTR (reverse DNS)", name.rstrip("."), "dnspython", confidence=Confidence.HIGH)
    ctx.check()
    ctx.emit("[i] Shodan InternetDB (indexed data, refreshed weekly)")
    data = ctx.http().get_json("internetdb", f"https://internetdb.shodan.io/{ctx.target}", ok_statuses=(200, 404))
    if not data:
        ctx.emit("[-] InternetDB has no data for this address")
        return findings
    note = "From Shodan's index (up to a week old), not a live scan."
    for port in data.get("ports", []):
        add("Indexed open port", f"{port}/tcp", "Shodan InternetDB", ResultKind.FOUND, notes=note)
    for host in data.get("hostnames", []):
        add("Indexed hostname", host, "Shodan InternetDB", ResultKind.FOUND)
    if data.get("tags"):
        add("Tags", ", ".join(data["tags"]), "Shodan InternetDB")
    if data.get("cpes"):
        add("Software (CPE)", ", ".join(data["cpes"][:20]), "Shodan InternetDB", confidence=Confidence.LOW, notes=note)
    if data.get("vulns"):
        add("Known CVEs (indexed)", ", ".join(data["vulns"][:30]), "Shodan InternetDB", ResultKind.FOUND,
            Confidence.LOW, "Matched by version banners; not confirmed. Never test these.")
    return findings


def console_tag(line: str) -> str:
    return {"[+]": "g", "[-]": "p", "[?]": "b"}.get(line[:3], "")


MODULE = ModuleSpec(
    number="13",
    id="reverseip",
    name=NAME,
    icon="rev",
    description="Hostnames and indexed open ports for an IP (InternetDB).",
    labels=("external", "passive"),
    target_types=(TargetType.IP,),
    provider="Shodan InternetDB (no key) and your DNS resolver",
    run=run,
    console_tag=console_tag,
    timeout_s=60,
)
