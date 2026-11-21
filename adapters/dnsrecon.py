"""05 DNSRecon: public DNS records with dnspython (queries go to the system resolver)."""

from __future__ import annotations

import dns.exception
import dns.resolver
import dns.reversename

from adapters._output import unreachable
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.net import NetError
from core.validation import TargetType

NAME = "DNSRecon"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")


def resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = 3.0
    r.lifetime = 6.0
    return r


def query(r: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
    """Record texts, or [] when there are none. Raises dns.exception.DNSException on failure
    (NoNameservers too: offline, every server fails, and that is not the same as "no records")."""
    answer = r.resolve(name, rtype, raise_on_no_answer=False)
    if answer.rrset is None:
        return []
    return sorted(rdata.to_text() for rdata in answer.rrset)


def ptr(r: dns.resolver.Resolver, ip: str) -> list[str]:
    try:
        return query(r, dns.reversename.from_address(ip).to_text(), "PTR")
    except dns.exception.DNSException:
        return []


def run(ctx) -> list[Finding]:
    r = resolver()
    findings = []
    failed: list[str] = []
    ctx.emit(f"[i] querying {', '.join(RECORD_TYPES)} for {ctx.target}")
    for rtype in RECORD_TYPES:
        ctx.check()
        try:
            records = query(r, ctx.target, rtype)
        except dns.resolver.NXDOMAIN:
            ctx.emit(f"[-] {ctx.target} does not exist (NXDOMAIN)")
            return [Finding(module=NAME, title="Domain does not exist", value="NXDOMAIN", source="dnspython",
                            confidence=Confidence.HIGH, result=ResultKind.INFO)]
        except dns.exception.DNSException as exc:
            reason = "timed out" if isinstance(exc, dns.exception.Timeout) else type(exc).__name__
            ctx.emit(f"[?] {rtype}: {reason}")
            failed.append(f"{rtype} {reason}")
            continue
        if not records:
            ctx.emit(f"[-] {rtype}: none")
            continue
        for record in records:
            ctx.emit(f"[+] {rtype:<5} {record}")
            findings.append(Finding(module=NAME, title=f"{rtype} record", value=record[:4000], source="dnspython",
                                    confidence=Confidence.HIGH, result=ResultKind.INFO))
    if len(failed) == len(RECORD_TYPES):
        raise NetError("No DNS answer: every query failed (" + ", ".join(failed) + "). "
                       "Check the network connection or the DNS resolver.")
    if failed:
        findings.append(unreachable(NAME, "DNS", "No answer for: " + ", ".join(failed)))
    return findings


def console_tag(line: str) -> str:
    return {"[+]": "g", "[-]": "p", "[?]": "b"}.get(line[:3], "")


MODULE = ModuleSpec(
    number="05",
    id="dnsrecon",
    name=NAME,
    icon="dns",
    description="A, AAAA, MX, NS, TXT, CNAME, SOA and CAA records.",
    labels=("passive",),
    target_types=(TargetType.DOMAIN,),
    provider="Your system's DNS resolver (public DNS)",
    run=run,
    console_tag=console_tag,
    timeout_s=60,
)
