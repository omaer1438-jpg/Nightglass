"""09 HeaderAnalyzer: response headers and missing security headers (one normal request)."""

from __future__ import annotations

from adapters._web import PAGE_OK, host_of, page_url
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "HeaderAnalyzer"
SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}
INTERESTING = ("server", "x-powered-by", "via", "content-type", "cache-control", "x-generator")


def analyze(status: int, final_url: str, headers: dict[str, str]) -> list[tuple[str, str, ResultKind]]:
    rows = [("Status", str(status), ResultKind.INFO), ("Final URL", final_url, ResultKind.INFO)]
    for key in INTERESTING:
        if key in headers:
            rows.append((f"Header {key}", headers[key], ResultKind.INFO))
    for key, title in SECURITY_HEADERS.items():
        if key in headers:
            rows.append((f"Present: {title}", headers[key], ResultKind.INFO))
        elif not (key == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", "")):
            rows.append((f"Missing: {title}", "Not sent by the server", ResultKind.FOUND))
    return rows


def run(ctx) -> list[Finding]:
    url = page_url(ctx.target_type, ctx.target)
    ctx.emit(f"[i] GET {url}")
    response = ctx.http().request(host_of(ctx.target_type, ctx.target), url, ok_statuses=PAGE_OK)
    findings = []
    for title, value, result in analyze(response.status, response.url, response.headers):
        ctx.emit(f"[{'-' if result is ResultKind.FOUND else '+'}] {title}: {value}")
        findings.append(Finding(module=NAME, title=title, value=value[:4000], source="httpx",
                                confidence=Confidence.HIGH, result=result))
    return findings


MODULE = ModuleSpec(
    number="09",
    id="headeranalyzer",
    name=NAME,
    icon="head",
    description="Response headers and missing security headers.",
    labels=("passive",),
    target_types=(TargetType.DOMAIN, TargetType.URL),
    provider="The site's own server (one normal page request)",
    run=run,
    console_tag=lambda line: "y" if line.startswith("[-]") else ("g" if line.startswith("[+]") else ""),
    timeout_s=45,
)
