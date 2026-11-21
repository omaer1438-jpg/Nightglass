"""15 PortScanner (ACTIVE, off by default): TCP connect check on a fixed list of common ports.

Only for systems you own or are authorized to test. Gated by the Settings switch,
the case's allowed modes and its authorized scope, and a fresh consent every run.
No payloads are sent: a port counts as open if a normal TCP connection succeeds.
For passive, indexed port data use 13 ReverseIP instead.
"""

from __future__ import annotations

import socket
import time

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "PortScanner"
#: Allowlisted ports (the "fixed command"): nothing outside this list is ever probed.
PORTS = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 8080: "http-alt", 8443: "https-alt",
}
CONNECT_TIMEOUT = 1.5
PAUSE = 0.1


def resolve(target_type: TargetType, target: str) -> str:
    if target_type is TargetType.IP:
        return target
    return socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)[0][4][0]


def is_open(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def run(ctx) -> list[Finding]:
    if not ctx.setting("active.port_scan", False):
        raise ValueError("Live port scans are off. Enable them in Settings first.")
    address = resolve(ctx.target_type, ctx.target)
    ctx.emit(f"[i] TCP connect check on {len(PORTS)} allowlisted ports of {address}")
    findings = []
    for port, service in PORTS.items():
        ctx.check()
        if is_open(address, port):
            ctx.emit(f"[+] {port}/tcp open ({service})")
            findings.append(Finding(module=NAME, title=f"Open port {port}/tcp", value=service, source="TCP connect",
                                    confidence=Confidence.HIGH, result=ResultKind.FOUND,
                                    notes="Live check at collection time; firewalls may differ per source address."))
        else:
            ctx.emit(f"[-] {port}/tcp closed or filtered")
        time.sleep(PAUSE)
    return findings


MODULE = ModuleSpec(
    number="15",
    id="portscanner",
    name=NAME,
    icon="port",
    description="Live port scan. Only for systems you own or are authorized to test.",
    labels=("active",),
    target_types=(TargetType.IP, TargetType.DOMAIN),
    provider="The target host itself (TCP connections to 19 common ports)",
    run=run,
    console_tag=lambda line: "g" if line.startswith("[+]") else "p",
    timeout_s=120,
    active_setting="active.port_scan",
)
