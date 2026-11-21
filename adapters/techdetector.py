"""10 TechDetector: likely server, CMS and frameworks from headers and HTML signatures."""

from __future__ import annotations

import re

from adapters._web import PAGE_OK, host_of, page_url
from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "TechDetector"

HEADER_SIGNS = [
    ("cf-ray", None, "Cloudflare (CDN)"),
    ("x-vercel-id", None, "Vercel (hosting)"),
    ("x-amz-cf-id", None, "Amazon CloudFront (CDN)"),
    ("x-github-request-id", None, "GitHub Pages (hosting)"),
    ("x-shopify-stage", None, "Shopify"),
    ("x-drupal-cache", None, "Drupal"),
    ("x-powered-by", r"php", "PHP"),
    ("x-powered-by", r"asp\.net", "ASP.NET"),
    ("x-powered-by", r"express", "Express (Node.js)"),
    ("x-powered-by", r"next\.js", "Next.js"),
    ("server", r"nginx", "nginx"),
    ("server", r"apache", "Apache HTTP Server"),
    ("server", r"microsoft-iis", "Microsoft IIS"),
    ("server", r"litespeed", "LiteSpeed"),
    ("server", r"cloudflare", "Cloudflare (CDN)"),
]
COOKIE_SIGNS = [
    (r"\bPHPSESSID=", "PHP"),
    (r"\bJSESSIONID=", "Java servlet container"),
    (r"\bASP\.NET_SessionId=", "ASP.NET"),
    (r"\blaravel_session=", "Laravel"),
    (r"\bwordpress_|wp-settings-", "WordPress"),
    (r"\b_shopify_", "Shopify"),
]
HTML_SIGNS = [
    (r"/wp-content/|/wp-includes/", "WordPress"),
    (r"/_next/static/", "Next.js"),
    (r"window\.__NUXT__|/_nuxt/", "Nuxt"),
    (r"\bng-version=", "Angular"),
    (r"data-reactroot|react-dom(\.production)?(\.min)?\.js", "React"),
    (r"jquery(-\d[\d.]*)?(\.min)?\.js", "jQuery"),
    (r"bootstrap(\.min)?\.(css|js)", "Bootstrap"),
    (r"cdn\.shopify\.com", "Shopify"),
    (r"Drupal\.settings|/sites/default/files/", "Drupal"),
    (r"/media/jui/|Joomla!", "Joomla"),
    (r"static\.wixstatic\.com", "Wix"),
    (r"static1\.squarespace\.com", "Squarespace"),
    (r"googletagmanager\.com/gtm\.js", "Google Tag Manager"),
    (r"googletagmanager\.com/gtag/js|google-analytics\.com/analytics\.js", "Google Analytics"),
]
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,120})', re.I)


def detect(headers: dict[str, str], html: str) -> list[tuple[str, str]]:
    """(technology, evidence) pairs, deduplicated."""
    found: dict[str, str] = {}
    for header, pattern, tech in HEADER_SIGNS:
        value = headers.get(header)
        if value is not None and (pattern is None or re.search(pattern, value, re.I)):
            found.setdefault(tech, f"header {header}: {value[:80]}")
    cookies = headers.get("set-cookie", "")
    for pattern, tech in COOKIE_SIGNS:
        if re.search(pattern, cookies):
            found.setdefault(tech, "cookie name")
    for pattern, tech in HTML_SIGNS:
        if re.search(pattern, html, re.I):
            found.setdefault(tech, f"page source matches {pattern.split('|')[0]}")
    generator = _GENERATOR.search(html)
    if generator:
        found.setdefault(generator.group(1).strip(), "meta generator tag")
    return list(found.items())


def run(ctx) -> list[Finding]:
    url = page_url(ctx.target_type, ctx.target)
    ctx.emit(f"[i] GET {url}")
    response = ctx.http().request(host_of(ctx.target_type, ctx.target), url, ok_statuses=PAGE_OK)
    html = response.text[:2_000_000]
    findings = []
    for tech, evidence in detect(response.headers, html):
        ctx.emit(f"[+] {tech}  ({evidence})")
        findings.append(Finding(module=NAME, title=f"Likely: {tech}", value=evidence, source="signatures",
                                confidence=Confidence.MEDIUM, result=ResultKind.INFO,
                                notes="Signature match; sites can hide or fake these markers."))
    if not findings:
        ctx.emit("[-] no known signatures matched")
    return findings


MODULE = ModuleSpec(
    number="10",
    id="techdetector",
    name=NAME,
    icon="cpu",
    description="Likely server, CMS and frameworks from headers and HTML.",
    labels=("passive",),
    target_types=(TargetType.DOMAIN, TargetType.URL),
    provider="The site's own server (one normal page request)",
    run=run,
    console_tag=lambda line: "g" if line.startswith("[+]") else "p",
    timeout_s=45,
)
