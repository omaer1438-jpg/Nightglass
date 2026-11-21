"""06 WHOIS / RDAP: registration data for domains and IP networks.

Uses IANA's RDAP bootstrap files to find the authoritative RDAP server, then
queries it directly (no third-party WHOIS aggregator).
"""

from __future__ import annotations

import ipaddress

from adapters._output import unexpected_output
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.net import NetError
from core.validation import TargetType

NAME = "WHOIS / RDAP"
BOOTSTRAP = {
    "domain": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}


def _https(urls: list[str]) -> str | None:
    return next((u for u in urls if u.startswith("https://")), None)


def server_for_domain(http, domain: str) -> str | None:
    data = http.get_json("rdap", BOOTSTRAP["domain"])
    labels = domain.lower().split(".")
    best, best_len = None, 0
    for entries, urls in data.get("services", []):
        for entry in entries:
            parts = entry.lower().split(".")
            if labels[-len(parts):] == parts and len(parts) > best_len:
                best, best_len = _https(urls), len(parts)
    return best


def server_for_ip(http, ip: str) -> str | None:
    address = ipaddress.ip_address(ip)
    data = http.get_json("rdap", BOOTSTRAP["ipv4" if address.version == 4 else "ipv6"])
    best, best_len = None, -1
    for entries, urls in data.get("services", []):
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if address in network and network.prefixlen > best_len:
                best, best_len = _https(urls), network.prefixlen
    return best


def lookup(http, kind: TargetType, value: str) -> dict | None:
    """RDAP object, or None if the registry has no record (404)."""
    base = server_for_domain(http, value) if kind is TargetType.DOMAIN else server_for_ip(http, value)
    if not base:
        raise NetError("No RDAP server is registered for this " + ("TLD." if kind is TargetType.DOMAIN else "network."))
    path = "domain" if kind is TargetType.DOMAIN else "ip"
    return http.get_json("rdap", f"{base.rstrip('/')}/{path}/{value}", ok_statuses=(200, 404),
                         headers={"Accept": "application/rdap+json"})


def vcard_name(entity: dict) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] in ("fn", "org") and isinstance(item[3], str) and item[3].strip():
            return item[3].strip()
    return None


def entities_by_role(obj: dict, role: str) -> list[str]:
    names = []
    for entity in obj.get("entities", []) or []:
        if role in (entity.get("roles") or []):
            name = vcard_name(entity)
            if name:
                names.append(name)
        names += entities_by_role(entity, role)  # nested entities (e.g. registrar abuse contact)
    return names


def events(obj: dict) -> dict[str, str]:
    return {e.get("eventAction"): (e.get("eventDate") or "")[:10] for e in obj.get("events", []) or []}


def summarize(kind: TargetType, data: dict) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    when = events(data)
    if kind is TargetType.DOMAIN:
        rows += [("Registrar", ", ".join(dict.fromkeys(entities_by_role(data, "registrar"))))]
        rows += [("Registrant", ", ".join(dict.fromkeys(entities_by_role(data, "registrant"))) or "Redacted / not public")]
        rows += [("Registered", when.get("registration", "")), ("Expires", when.get("expiration", "")),
                 ("Last changed", when.get("last changed", ""))]
        rows += [("Name servers", ", ".join(sorted(ns.get("ldhName", "").lower() for ns in data.get("nameservers", []) or [])))]
        rows += [("Status", ", ".join(data.get("status", []) or []))]
        secure = (data.get("secureDNS") or {}).get("delegationSigned")
        if secure is not None:
            rows.append(("DNSSEC", "Signed" if secure else "Not signed"))
    else:
        rows += [("Network name", data.get("name") or ""), ("Handle", data.get("handle") or "")]
        if data.get("startAddress"):
            rows.append(("Range", f"{data.get('startAddress')} – {data.get('endAddress')}"))
        rows += [("Country", data.get("country") or ""), ("Type", data.get("type") or "")]
        owners = entities_by_role(data, "registrant") or entities_by_role(data, "administrative")
        rows.append(("Network owner", ", ".join(dict.fromkeys(owners))))
        rows += [("Registered", when.get("registration", "")), ("Last changed", when.get("last changed", ""))]
    return [(k, v) for k, v in rows if v]


@unexpected_output("the RDAP registry")
def run(ctx) -> list[Finding]:
    http = ctx.http()
    ctx.emit("[i] finding the authoritative RDAP server via the IANA bootstrap")
    data = lookup(http, ctx.target_type, ctx.target)
    if data is None:
        ctx.emit("[-] no RDAP record (404)")
        return [Finding(module=NAME, title="No registration record", value="The registry returned 404.",
                        source="RDAP", confidence=Confidence.MEDIUM, result=ResultKind.INFO)]
    findings = []
    link = next((l.get("href") for l in data.get("links", []) or [] if l.get("rel") == "self"), None)
    for title, value in summarize(ctx.target_type, data):
        ctx.emit(f"[+] {title}: {value}")
        findings.append(Finding(module=NAME, title=title, value=value[:4000], source="RDAP",
                                url=link if link and link.startswith("https://") else None,
                                confidence=Confidence.HIGH, result=ResultKind.INFO))
    return findings


MODULE = ModuleSpec(
    number="06",
    id="rdap",
    name=NAME,
    icon="globe",
    description="Registrar, dates, name servers and network owner (RDAP).",
    labels=("external", "passive"),
    target_types=(TargetType.DOMAIN, TargetType.IP),
    provider="IANA's RDAP bootstrap, then the registry's own RDAP server",
    run=run,
    timeout_s=60,
)
