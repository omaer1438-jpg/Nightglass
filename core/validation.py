"""Type-checked target input (docs/PROJECT_RULES.md rule 3).

Every identifier is validated and normalized here before it is stored or handed
to any tool. Values that pass are safe to use as a single argv element: none can
start with "-" and none contain whitespace or control characters (except "other",
which is never passed to a tool).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


class TargetType(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE = "file"
    OTHER = "other"

    @property
    def label(self) -> str:
        return _LABELS[self]


_LABELS = {
    TargetType.USERNAME: "Username",
    TargetType.EMAIL: "Email",
    TargetType.PHONE: "Phone",
    TargetType.IP: "IP address",
    TargetType.DOMAIN: "Domain",
    TargetType.URL: "URL",
    TargetType.FILE: "Image / file",
    TargetType.OTHER: "Other",
}


class ValidationError(ValueError):
    """Input does not match its declared type. The message is shown to the user."""


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_USERNAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
_EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9_+][A-Za-z0-9._%+-]{0,63}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_E164 = re.compile(r"^\+[1-9]\d{6,14}$")
_PHONE_SEPARATORS = re.compile(r"[\s().-]")

MAX_URL_LENGTH = 2048
MAX_OTHER_LENGTH = 256


def validate_target(target_type: TargetType | str, raw: str) -> str:
    """Return the normalized value, or raise ValidationError."""
    kind = TargetType(target_type)
    value = (raw or "").strip()
    if not value:
        raise ValidationError(f"Enter a {kind.label.lower()}.")
    if _CONTROL.search(value):
        raise ValidationError("Remove line breaks and control characters.")
    return _VALIDATORS[kind](value)


def fingerprint(target_type: TargetType | str, normalized: str) -> str:
    """Stable SHA-256 of a normalized target, used to spot duplicates."""
    kind = TargetType(target_type)
    return hashlib.sha256(f"{kind.value}:{normalized}".encode("utf-8")).hexdigest()


def detect_type(raw: str) -> TargetType | None:
    """Best-effort guess for the quick-lookup "Auto" mode. Files are never guessed."""
    value = (raw or "").strip()
    if not value:
        return None
    for kind in (
        TargetType.URL,
        TargetType.EMAIL,
        TargetType.IP,
        TargetType.PHONE,
        TargetType.DOMAIN,
        TargetType.USERNAME,
    ):
        if kind is TargetType.URL and "://" not in value:
            continue
        try:
            validate_target(kind, value)
        except ValidationError:
            continue
        return kind
    return None


def _username(value: str) -> str:
    value = value.removeprefix("@")
    if not _USERNAME.match(value):
        raise ValidationError(
            "Usernames use letters, digits, dot, dash or underscore (max 64), "
            "and can't start with a dot or dash."
        )
    return value


def _domain(value: str) -> str:
    host = value.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError("That isn't a valid domain name.") from exc
    labels = host.split(".")
    if (
        len(host) > 253
        or len(labels) < 2
        or not all(_LABEL.match(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise ValidationError("Enter a domain like example.com.")
    return host


def _email(value: str) -> str:
    if value.count("@") != 1:
        raise ValidationError("Enter an email like name@example.com.")
    local, _, domain = value.partition("@")
    if not _EMAIL_LOCAL.match(local) or ".." in local or local.endswith("."):
        raise ValidationError("Enter an email like name@example.com.")
    try:
        domain = _domain(domain)
    except ValidationError as exc:
        raise ValidationError("The part after @ isn't a valid domain.") from exc
    normalized = f"{local}@{domain}"
    if len(normalized) > 254:
        raise ValidationError("Email addresses can be at most 254 characters.")
    return normalized


def _phone(value: str) -> str:
    compact = _PHONE_SEPARATORS.sub("", value)
    if compact.startswith("00"):
        compact = "+" + compact[2:]
    if not _E164.match(compact):
        raise ValidationError(
            "Use international E.164 format with a country code, like +1 555 010 0123."
        )
    return compact


def _ip(value: str) -> str:
    if "%" in value:  # an IPv6 zone id ("fe80::1%x?a=b") is free text that would end up inside request URLs
        raise ValidationError("Remove the %zone part from the IPv6 address.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValidationError("Enter an IPv4 or IPv6 address, like 192.0.2.10.") from exc


def _url(value: str) -> str:
    if len(value) > MAX_URL_LENGTH:
        raise ValidationError(f"URLs can be at most {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() for ch in value):
        raise ValidationError("URLs can't contain spaces.")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ValidationError("That isn't a valid URL.") from exc
    if parts.scheme.lower() not in ("http", "https"):
        raise ValidationError("Only http:// and https:// URLs are supported.")
    if parts.username or parts.password:
        raise ValidationError("Remove the login details from the URL.")
    host = parts.hostname or ""
    try:
        host = _ip(host.strip("[]"))
        if ":" in host:
            host = f"[{host}]"
    except ValidationError:
        try:
            host = _domain(host)
        except ValidationError as exc:
            raise ValidationError("The URL needs a valid host, like https://example.com.") from exc
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))


def _file(value: str) -> str:
    path = Path(value).expanduser()
    if not path.is_file():
        raise ValidationError("Choose a file that exists on this computer.")
    return str(path.resolve())


def _other(value: str) -> str:
    if len(value) > MAX_OTHER_LENGTH:
        raise ValidationError(f"Keep this under {MAX_OTHER_LENGTH} characters.")
    return value


_VALIDATORS = {
    TargetType.USERNAME: _username,
    TargetType.EMAIL: _email,
    TargetType.PHONE: _phone,
    TargetType.IP: _ip,
    TargetType.DOMAIN: _domain,
    TargetType.URL: _url,
    TargetType.FILE: _file,
    TargetType.OTHER: _other,
}
