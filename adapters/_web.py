"""Shared helpers for modules that look at one web host (HeaderAnalyzer, TechDetector, SSLChecker)."""

from __future__ import annotations

from urllib.parse import urlsplit

from core.validation import TargetType

#: Only a real page is analysed: an error, block or rate-limit page (4xx/5xx) fails the run with its reason.
PAGE_OK = tuple(range(200, 400))


def page_url(target_type: TargetType, target: str) -> str:
    """https://<domain>/ for domains; URLs are used as given (already validated http/https)."""
    return f"https://{target}/" if target_type is TargetType.DOMAIN else target


def host_of(target_type: TargetType, target: str) -> str:
    return target if target_type is TargetType.DOMAIN else (urlsplit(target).hostname or "")
