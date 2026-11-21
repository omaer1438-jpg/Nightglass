"""HTTP for built-in modules: per-provider rate limits, a 24 h cache, size limits.

Used from worker threads, so the cache opens its own short-lived SQLite
connections. API keys travel in headers only and are never part of cache keys
or logs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import sqlite3
import threading
import time
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import httpx

from core import __version__

USER_AGENT = f"Nightglass/{__version__} (personal OSINT workbench)"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=10.0)
CACHE_TTL = timedelta(hours=24)

#: Minimum seconds between requests to the same provider (free tiers, politeness).
DEFAULT_INTERVAL = 1.0
RATE_LIMITS: dict[str, float] = {
    "crt.sh": 3.0,
    "rdap": 1.0,
    "ipinfo": 1.0,
    "internetdb": 1.0,
    "github": 1.0,
    "hibp": 6.5,  # HIBP's lowest tier allows ~10 requests/minute
    "web": 1.0,
    "wayback": 1.5,
    "urlscan": 2.0,
    "gravatar": 1.0,
    "kickbox": 1.0,
}

_rate_lock = threading.Lock()
_last_call: dict[str, float] = {}


class NetError(Exception):
    """A provider could not be reached or answered with an error. Shown to the user."""


class Cancelled(Exception):
    pass


class ApiCache:
    def __init__(self, db_path: Path | None, enabled: bool):
        self.db_path = db_path
        self.enabled = enabled and db_path is not None and str(db_path) != ":memory:"

    @staticmethod
    def key(url: str, params: dict | None) -> str:
        return hashlib.sha256(f"{url}?{urlencode(sorted((params or {}).items()))}".encode()).hexdigest()

    def get(self, provider: str, key: str):
        if not self.enabled:
            return None
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute("SELECT response, fetched_at FROM api_cache WHERE provider = ? AND key = ?",
                               (provider, key)).fetchone()
        if not row or datetime.now(timezone.utc) - datetime.fromisoformat(row[1]) > CACHE_TTL:
            return None
        return json.loads(row[0])

    def put(self, provider: str, key: str, data) -> None:
        if not self.enabled:
            return
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.execute(
                "INSERT INTO api_cache (provider, key, response, fetched_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(provider, key) DO UPDATE SET response = excluded.response, fetched_at = excluded.fetched_at",
                (provider, key, json.dumps(data), datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    content: bytes
    url: str
    http_version: str

    def json(self):
        return json.loads(self.content)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


class Http:
    """One per run. `check` raises if the run was cancelled or timed out."""

    def __init__(self, cache: ApiCache, check: Callable[[], None] = lambda: None,
                 transport: httpx.BaseTransport | None = None):
        self.cache = cache
        self.check = check
        self._transport = transport
        self._client: httpx.Client | None = None
        self.requests = 0
        self.cache_hits = 0
        self._origin = ""                  # host of the current request, before any redirect
        self._own_headers: set[str] = set()  # the caller's headers (API keys) for that host only

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=DEFAULT_TIMEOUT, follow_redirects=True, max_redirects=5,
                headers={"User-Agent": USER_AGENT}, transport=self._transport,
                event_hooks={"request": [self._guard_redirect]},
            )
        return self._client

    def _guard_redirect(self, request: httpx.Request) -> None:
        """Every request of a redirect chain: another host gets no key headers and must not be internal."""
        if request.url.host == self._origin:
            return
        for name in self._own_headers:
            request.headers.pop(name, None)
        if _is_internal(request.url.host):
            raise NetError("The site redirected to a private or local address; not followed.")

    def _wait_turn(self, provider: str) -> None:
        interval = RATE_LIMITS.get(provider, DEFAULT_INTERVAL)
        while True:
            self.check()
            with _rate_lock:
                now = time.monotonic()
                wait = _last_call.get(provider, 0.0) + interval - now
                if wait <= 0:
                    _last_call[provider] = now
                    return
            time.sleep(min(wait, 0.25))

    def request(self, provider: str, url: str, *, method: str = "GET", params: dict | None = None,
                headers: dict | None = None, ok_statuses: tuple[int, ...] = (200,),
                timeout: float | None = None) -> HttpResult:
        if not url.startswith("https://") and not url.startswith("http://"):
            raise NetError("Only http(s) requests are allowed.")
        self._wait_turn(provider)
        self.requests += 1
        self._origin, self._own_headers = httpx.URL(url).host, set(headers or {})
        try:
            extra = {"timeout": httpx.Timeout(timeout, connect=10.0)} if timeout else {}
            with self._http().stream(method, url, params=params, headers=headers, **extra) as response:
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise NetError(f"{provider} sent more than {MAX_RESPONSE_BYTES // (1024 * 1024)} MB; stopped.")
                    chunks.append(chunk)
                    self.check()
                result = HttpResult(response.status_code, {k.lower(): v for k, v in response.headers.items()},
                                    b"".join(chunks), str(response.url), response.http_version)
        except httpx.TimeoutException as exc:
            raise NetError(f"{provider} did not answer in time.") from exc
        except httpx.HTTPError as exc:
            raise NetError(f"Could not reach {provider}: {type(exc).__name__}.") from exc
        if result.status not in ok_statuses:
            raise NetError(_status_message(provider, result.status))
        return result

    def get_json(self, provider: str, url: str, *, params: dict | None = None, headers: dict | None = None,
                 ok_statuses: tuple[int, ...] = (200,), use_cache: bool = True, timeout: float | None = None):
        """JSON body (None for an allowed non-200 such as 404). Cached for 24 h when enabled."""
        key = ApiCache.key(url, params)
        if use_cache:
            cached = self.cache.get(provider, key)
            if cached is not None:
                self.cache_hits += 1
                return cached["body"]
        response = self.request(provider, url, params=params, headers=headers, ok_statuses=ok_statuses,
                                timeout=timeout)
        body = None
        if response.status == 200 and response.content:
            try:
                body = response.json()
            except ValueError as exc:
                raise NetError(f"{provider} returned something that isn't JSON.") from exc
        if use_cache:
            self.cache.put(provider, key, {"body": body})
        return body

    def close(self) -> None:
        if self._client is not None:
            self._client.close()


def _is_internal(host: str) -> bool:
    """Loopback, private, link-local or otherwise non-public (a DNS name is resolved first)."""
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError):
        return False  # unresolvable: the request itself fails
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global or ip.is_multicast:
            return True
    return False


def _status_message(provider: str, status: int) -> str:
    if status == 401:
        return f"{provider} rejected the API key (401). Check it in Settings."
    if status == 403:
        return f"{provider} refused the request (403)."
    if status == 429:
        return f"{provider} rate-limited this request (429). Try again later."
    if status >= 500:
        return f"{provider} had a server error ({status}). Try again later."
    return f"{provider} answered with HTTP {status}."
