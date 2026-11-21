"""18 EmailHeaders: where a saved email came from. Reads an .eml file on this computer; nothing is sent."""

from __future__ import annotations

import email
import email.policy
import ipaddress
import re
from email.utils import parseaddr
from pathlib import Path

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "EmailHeaders"
SOURCE = "Email headers"
HOW_TO = "Save the message as an .eml file (Gmail: More > Download message; Outlook: Save as), then choose it."
ORIGIN_NOTE = "The first public server in the chain. Usually the mail provider's server, not the sender's device."
FORGED_NOTE = "Lines added before your provider's servers can be forged. Trust the newest hops most."
MISMATCH_NOTE = "Common in phishing, but also in newsletters and mailing lists. Not proof of fraud."
MAX_BYTES = 30 * 1024 * 1024
FACTS = {"From": "From", "Reply-To": "Reply-To", "Return-Path": "Return-Path", "To": "To", "Subject": "Subject",
         "Date": "Date", "Message-ID": "Message ID"}
_ADDRESS = re.compile(r"[\[(]((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+)[\])]")
_AUTH = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)


def public_ips(text: str) -> list[str]:
    """Public addresses in a header line, in order. Private and reserved ones are internal hops."""
    found = []
    for candidate in _ADDRESS.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.is_global and str(address) not in found:
            found.append(str(address))
    return found


def _domain(header: str) -> str:
    return parseaddr(header)[1].rpartition("@")[2].lower()


def analyze(raw: bytes) -> list[Finding]:
    message = email.message_from_bytes(raw, policy=email.policy.default)
    received = [" ".join(str(line).split()) for line in message.get_all("Received", [])]
    if not received and not message["From"]:
        raise ValueError(f"This file has no email headers. {HOW_TO}")

    def fact(title, value, notes="", result=ResultKind.INFO, confidence=Confidence.HIGH):
        return Finding(module=NAME, title=title, value=str(value)[:4000], source=SOURCE, confidence=confidence,
                       result=result, notes=notes)

    findings = [fact(title, message[key]) for key, title in FACTS.items() if message[key]]
    hops = list(reversed(received))  # the oldest hop is the last header
    sending = [public_ips(hop.split(" by ")[0]) for hop in hops]
    origin = next((ips[0] for ips in sending if ips), None)
    if origin:
        findings.append(fact("Originating server IP", origin, ORIGIN_NOTE, ResultKind.FOUND, Confidence.MEDIUM))
    for key in ("X-Originating-IP", "X-Sender-IP"):
        for address in public_ips(f"[{str(message[key] or '').strip(' []')}]"):
            findings.append(fact(key, address, ORIGIN_NOTE, ResultKind.FOUND, Confidence.LOW))
    results = {}
    for header in message.get_all("Authentication-Results", []):
        for check, verdict in _AUTH.findall(str(header)):
            results.setdefault(check.upper(), verdict.lower())
    findings += [fact(check, verdict, "As recorded by the receiving server.") for check, verdict in results.items()]
    sender = _domain(str(message["From"] or ""))
    for key in ("Reply-To", "Return-Path"):
        other = _domain(str(message[key] or ""))
        if sender and other and other != sender and not other.endswith("." + sender):
            findings.append(fact(f"{key} differs from From", f"{sender} / {other}", MISMATCH_NOTE, ResultKind.UNCERTAIN,
                                 Confidence.MEDIUM))
    findings += [fact(f"Hop {number}", hop, FORGED_NOTE) for number, hop in enumerate(hops, start=1)]
    return findings


def run(ctx) -> list[Finding]:
    path = Path(ctx.target)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("This file is too large to be a saved email.")
    findings = analyze(path.read_bytes())
    for finding in findings:
        ctx.emit(f"[+] {finding.title}: {finding.value}")
    return findings


MODULE = ModuleSpec(
    number="18",
    id="emailheaders",
    name=NAME,
    icon="mail",
    description="Sending server IP, route and SPF/DKIM/DMARC results of a saved email.",
    labels=("local",),
    target_types=(TargetType.FILE,),
    provider="None: it reads a file on this computer",
    run=run,
    timeout_s=30,
    notes=HOW_TO,
)
