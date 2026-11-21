"""04 IPLocation: a site's IP addresses, approximate network location (ipinfo) and network owner (RDAP)."""

from __future__ import annotations

import socket

from adapters import rdap
from adapters._output import unexpected_output
from adapters._web import host_of
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.net import NetError
from core.validation import TargetType

NAME = "IPLocation"
CAVEAT = "Approximate location of the network or ISP, not of a person."


def addresses_of(ctx) -> list[str]:
    """The target itself, or a domain's or URL's IPv4 addresses first, then IPv6."""
    if ctx.target_type is TargetType.IP:
        return [ctx.target]
    host = host_of(ctx.target_type, ctx.target)
    ctx.emit(f"[i] resolving {host}")
    try:
        found = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise NetError(f"Could not find an IP address for {host}.") from exc
    return sorted({info[4][0] for info in found}, key=lambda address: (":" in address, address))


@unexpected_output("ipinfo or RDAP")
def run(ctx) -> list[Finding]:
    addresses = addresses_of(ctx)
    address = addresses[0]
    http = ctx.http()
    headers = {"Accept": "application/json"}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"
    ctx.emit(f"[i] ipinfo.io lookup for {address}" + (" (with token)" if ctx.api_key else " (no token, low limits)"))
    data = http.get_json("ipinfo", f"https://ipinfo.io/{address}/json", headers=headers) or {}
    findings: list[Finding] = []

    def add(title, value, confidence=Confidence.MEDIUM, notes=""):
        if value in (None, ""):
            return
        ctx.emit(f"[+] {title}: {value}")
        findings.append(Finding(module=NAME, title=title, value=str(value), source="ipinfo", confidence=confidence,
                                result=ResultKind.INFO, notes=notes))

    if ctx.target_type is not TargetType.IP:
        for found_address in addresses:
            add("IP address", found_address, Confidence.HIGH, "A shared host or CDN address, not a person's.")
    if data.get("bogon"):
        add("Private or reserved address", "This address is not routed on the public internet.", Confidence.HIGH)
        return findings
    place = ", ".join(p for p in (data.get("city"), data.get("region"), data.get("country")) if p)
    add("Approximate location", place, Confidence.LOW, CAVEAT)
    add("Postal code (approximate)", data.get("postal"), Confidence.LOW, CAVEAT)
    add("Coordinates (approximate)", data.get("loc"), Confidence.LOW, CAVEAT)
    add("Time zone", data.get("timezone"))
    add("ISP / organization (ASN)", data.get("org"), Confidence.HIGH)
    add("Hostname", data.get("hostname"), Confidence.HIGH)
    try:
        ctx.emit("[i] RDAP lookup for the network owner")
        record = rdap.lookup(http, TargetType.IP, address)
    except NetError as exc:
        ctx.emit(f"[?] RDAP: {exc}")
        record = None
    if record:
        for title, value in rdap.summarize(TargetType.IP, record):
            if title in ("Network name", "Range", "Network owner"):
                ctx.emit(f"[+] {title}: {value}")
                findings.append(Finding(module=NAME, title=title, value=value, source="RDAP",
                                        confidence=Confidence.HIGH, result=ResultKind.INFO))
    return findings


MODULE = ModuleSpec(
    number="04",
    id="iplocation",
    name=NAME,
    icon="pin",
    description="IP addresses of a site, plus approximate network location, ISP and ASN.",
    labels=("external", "passive"),
    target_types=(TargetType.IP, TargetType.DOMAIN, TargetType.URL),
    provider="Your DNS resolver, ipinfo.io, then the RDAP registry for the network",
    run=run,
    api_key="ipinfo",
    timeout_s=60,
    notes=CAVEAT,
)
