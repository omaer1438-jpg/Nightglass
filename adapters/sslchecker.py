"""08 SSLChecker: one normal TLS handshake; certificate issuer, dates, SANs and protocol."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from adapters._web import host_of
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "SSLChecker"


def _name(parts) -> str:
    fields = {k: v for rdn in parts or () for k, v in rdn}
    return ", ".join(v for k, v in fields.items() if k in ("commonName", "organizationName")) or "—"


def handshake(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return {"verified": True, "cert": tls.getpeercert(), "version": tls.version(),
                        "cipher": tls.cipher()[0] if tls.cipher() else ""}
    except ssl.SSLCertVerificationError as exc:
        return {"verified": False, "error": exc.verify_message or str(exc)}


def run(ctx) -> list[Finding]:
    host = host_of(ctx.target_type, ctx.target)
    ctx.emit(f"[i] TLS handshake with {host}:443")
    try:
        info = handshake(host)
    except (OSError, ssl.SSLError) as exc:
        raise ValueError(f"Could not connect to {host}:443 ({type(exc).__name__}).") from exc
    findings: list[Finding] = []

    def add(title, value, result=ResultKind.INFO, confidence=Confidence.HIGH, notes=""):
        ctx.emit(f"[+] {title}: {value}")
        findings.append(Finding(module=NAME, title=title, value=str(value)[:4000], source="Python ssl",
                                result=result, confidence=confidence, notes=notes))

    if not info["verified"]:
        add("Certificate not trusted", info["error"], ResultKind.FOUND,
            notes="Verification failed, so no certificate details were read.")
        return findings
    cert = info["cert"]
    add("Certificate trusted", "Yes (chain and hostname verified)")
    add("Subject", _name(cert.get("subject")))
    add("Issuer", _name(cert.get("issuer")))
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    days = (not_after - datetime.now(timezone.utc)).days
    add("Valid from", not_before.date().isoformat())
    add("Valid until", f"{not_after.date().isoformat()} ({days} days left)",
        ResultKind.FOUND if days < 21 else ResultKind.INFO)
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if sans:
        add("Subject alternative names", ", ".join(sans[:100]) + (" …" if len(sans) > 100 else ""))
    add("Protocol", info["version"])
    add("Cipher", info["cipher"])
    return findings


MODULE = ModuleSpec(
    number="08",
    id="sslchecker",
    name=NAME,
    icon="lock",
    description="Certificate issuer, validity, SANs and protocol.",
    labels=("passive",),
    target_types=(TargetType.DOMAIN, TargetType.URL),
    provider="The site's own server (one normal HTTPS handshake)",
    run=run,
    timeout_s=30,
)
