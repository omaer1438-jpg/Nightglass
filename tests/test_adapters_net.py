"""Built-in modules with mocked network (httpx.MockTransport) and mocked DNS/sockets.

Fake data only: example.com, 192.0.2.0/24, 203.0.113.0/24, example_user, +1 555 numbers.
"""

from __future__ import annotations

import json
import threading
import time

import httpx
import phonenumbers
import pytest

import core.net as net
from adapters import (
    blackbird,
    breachchecker,
    dnsrecon,
    githubrecon,
    headeranalyzer,
    iplocation,
    phoneintel,
    portscanner,
    rdap,
    reverseip,
    sslchecker,
    subdomainscan,
    techdetector,
)
from core.db import Database
from core.findings import ResultKind
from core.modules import discover
from core.net import ApiCache, Http, NetError
from core.runner import JobCancelled, ModuleContext
from core.validation import TargetType


@pytest.fixture(autouse=True)
def no_rate_limits(monkeypatch):
    monkeypatch.setattr(net, "RATE_LIMITS", {})
    monkeypatch.setattr(net, "DEFAULT_INTERVAL", 0.0)
    monkeypatch.setattr(net, "_last_call", {})


def ctx_for(kind, target, routes=None, api_key=None, settings=None, cache=None, seen=None):
    """ModuleContext whose HTTP goes to `routes` {url-prefix: (status, json|bytes, headers)}."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if seen is not None:
            seen.append(request)
        for prefix, (status, body, headers) in (routes or {}).items():
            if url.startswith(prefix):
                content = body if isinstance(body, bytes) else json.dumps(body).encode()
                return httpx.Response(status, content=content, headers=headers or {})
        return httpx.Response(599, content=b"unrouted " + url.encode())

    lines: list[str] = []
    services = {
        "http_factory": lambda check: Http(cache or ApiCache(None, False), check, transport=httpx.MockTransport(handler)),
        "settings": settings or {},
    }
    if api_key:
        services["api_key"] = api_key
    ctx = ModuleContext(TargetType(kind), target, None, lines.append, threading.Event(), services)
    return ctx, lines


def titles(findings):
    return {f.title: f.value for f in findings}


def test_registry_has_all_modules():
    numbers = [m.number for m in discover()]
    assert numbers == [f"{n:02d}" for n in range(1, 29)]


# ---------------------------------------------------------------- local / dns / sockets


def test_phoneintel_fictional_and_valid_numbers():
    ctx, lines = ctx_for("phone", "+15550100123")
    found = titles(phoneintel.run(ctx))
    assert found["Valid number"] == "No"  # +1 555 numbers are fictional
    assert found["Country calling code"] == "+1"

    example = phonenumbers.example_number_for_type("GB", phonenumbers.PhoneNumberType.MOBILE)
    e164 = phonenumbers.format_number(example, phonenumbers.PhoneNumberFormat.E164)
    found = titles(phoneintel.run(ctx_for("phone", e164)[0]))
    assert found["Valid number"] == "Yes"
    assert found["Line type"] == "mobile"
    assert "GB" in found["Country"]


def test_dnsrecon(monkeypatch):
    records = {"A": ["192.0.2.10"], "MX": ["10 mail.example.com."], "TXT": ['"v=spf1 -all"']}
    monkeypatch.setattr(dnsrecon, "query", lambda r, name, rtype: records.get(rtype, []))
    ctx, lines = ctx_for("domain", "example.com")
    findings = dnsrecon.run(ctx)
    assert [(f.title, f.value) for f in findings] == [
        ("A record", "192.0.2.10"), ("MX record", "10 mail.example.com."), ("TXT record", '"v=spf1 -all"'),
    ]
    assert all(f.result is ResultKind.INFO for f in findings)

    def nx(r, name, rtype):
        raise dnsrecon.dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dnsrecon, "query", nx)
    assert [f.title for f in dnsrecon.run(ctx_for("domain", "nope.example.com")[0])] == ["Domain does not exist"]


def test_sslchecker(monkeypatch):
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example CA R1"),)),
        "notBefore": "Oct  1 00:00:00 2026 GMT",
        "notAfter": "Dec 30 00:00:00 2099 GMT",
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }
    monkeypatch.setattr(sslchecker, "handshake", lambda host: {"verified": True, "cert": cert,
                                                               "version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"})
    found = titles(sslchecker.run(ctx_for("url", "https://www.example.com/login")[0]))
    assert found["Issuer"] == "Example CA, Example CA R1"
    assert found["Subject alternative names"] == "example.com, www.example.com"
    assert found["Protocol"] == "TLSv1.3"

    monkeypatch.setattr(sslchecker, "handshake", lambda host: {"verified": False, "error": "certificate has expired"})
    [finding] = sslchecker.run(ctx_for("domain", "example.com")[0])
    assert finding.title == "Certificate not trusted" and finding.result is ResultKind.FOUND


def test_portscanner_only_probes_allowlist(monkeypatch):
    probed = []
    monkeypatch.setattr(portscanner, "is_open", lambda addr, port: probed.append((addr, port)) or port == 443)
    monkeypatch.setattr(portscanner, "PAUSE", 0)
    with pytest.raises(ValueError, match="off"):
        portscanner.run(ctx_for("ip", "192.0.2.10")[0])
    ctx, _ = ctx_for("ip", "192.0.2.10", settings={"active.port_scan": True})
    findings = portscanner.run(ctx)
    assert [f.title for f in findings] == ["Open port 443/tcp"]
    assert {port for _, port in probed} == set(portscanner.PORTS)
    assert portscanner.MODULE.is_active and portscanner.MODULE.active_setting == "active.port_scan"


# ---------------------------------------------------------------- web APIs

RDAP_BOOT = {"services": [[["com", "net"], ["https://rdap.example-registry.test/"]]]}
RDAP_BOOT_V4 = {"services": [[["192.0.0.0/8"], ["https://rdap.example-rir.test/"]]]}
DOMAIN_RECORD = {
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2099-08-13T04:00:00Z"}],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                  ["fn", {}, "text", "Example Registrar"]]]}],
    "secureDNS": {"delegationSigned": True},
    "links": [{"rel": "self", "href": "https://rdap.example-registry.test/domain/example.com"}],
}
IP_RECORD = {"name": "EXAMPLE-NET", "handle": "NET-192-0-2-0-1", "startAddress": "192.0.2.0",
             "endAddress": "192.0.2.255", "country": "ZZ", "type": "ASSIGNMENT",
             "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]}]}


def test_rdap_domain_and_ip():
    routes = {
        rdap.BOOTSTRAP["domain"]: (200, RDAP_BOOT, None),
        "https://rdap.example-registry.test/domain/example.com": (200, DOMAIN_RECORD, None),
    }
    found = titles(rdap.run(ctx_for("domain", "example.com", routes)[0]))
    assert found["Registrar"] == "Example Registrar"
    assert found["Registered"] == "1995-08-14"
    assert found["Name servers"] == "a.iana-servers.net, b.iana-servers.net"
    assert found["DNSSEC"] == "Signed"
    assert found["Registrant"] == "Redacted / not public"

    routes = {
        rdap.BOOTSTRAP["ipv4"]: (200, RDAP_BOOT_V4, None),
        "https://rdap.example-rir.test/ip/192.0.2.10": (200, IP_RECORD, None),
    }
    found = titles(rdap.run(ctx_for("ip", "192.0.2.10", routes)[0]))
    assert found["Network owner"] == "Example Org"
    assert found["Range"] == "192.0.2.0 – 192.0.2.255"

    routes = {rdap.BOOTSTRAP["domain"]: (200, RDAP_BOOT, None),
              "https://rdap.example-registry.test/": (404, b"", None)}
    assert [f.title for f in rdap.run(ctx_for("domain", "example.com", routes)[0])] == ["No registration record"]
    with pytest.raises(NetError, match="No RDAP server"):
        rdap.run(ctx_for("domain", "example.org", {rdap.BOOTSTRAP["domain"]: (200, RDAP_BOOT, None)})[0])


def test_iplocation_uses_token_header_and_marks_location_approximate():
    seen = []
    routes = {
        "https://ipinfo.io/203.0.113.5/json": (200, {"ip": "203.0.113.5", "city": "Example City",
                                                     "country": "ZZ", "org": "AS64500 Example ISP",
                                                     "loc": "0.0,0.0", "timezone": "UTC"}, None),
        rdap.BOOTSTRAP["ipv4"]: (200, {"services": []}, None),
    }
    ctx, lines = ctx_for("ip", "203.0.113.5", routes, api_key="example-token", seen=seen)
    findings = iplocation.run(ctx)
    found = titles(findings)
    assert found["Approximate location"] == "Example City, ZZ"
    assert found["ISP / organization (ASN)"] == "AS64500 Example ISP"
    assert all("not of a person" in f.notes for f in findings if "pproximate" in f.title)
    assert seen[0].headers["authorization"] == "Bearer example-token"
    assert "example-token" not in " ".join(lines)  # keys never reach the console/log

    routes = {"https://ipinfo.io/192.0.2.1/json": (200, {"ip": "192.0.2.1", "bogon": True}, None)}
    assert [f.title for f in iplocation.run(ctx_for("ip", "192.0.2.1", routes)[0])] == ["Private or reserved address"]


def test_iplocation_finds_the_ip_of_a_site(monkeypatch):
    calls = []

    def fake_getaddrinfo(host, *args, **kwargs):
        calls.append(host)
        if host == "missing.example.com":
            raise OSError("no such host")
        return [(2, 1, 6, "", ("203.0.113.5", 0)), (23, 1, 6, "", ("2001:db8::5", 0, 0, 0))]

    monkeypatch.setattr(iplocation.socket, "getaddrinfo", fake_getaddrinfo)
    routes = {
        "https://ipinfo.io/203.0.113.5/json": (200, {"ip": "203.0.113.5", "org": "AS64500 Example ISP"}, None),
        rdap.BOOTSTRAP["ipv4"]: (200, {"services": []}, None),
    }
    findings = iplocation.run(ctx_for("url", "https://www.example.com/login", routes)[0])
    assert calls == ["www.example.com"]
    assert [f.value for f in findings if f.title == "IP address"] == ["203.0.113.5", "2001:db8::5"]
    assert titles(findings)["ISP / organization (ASN)"] == "AS64500 Example ISP"
    with pytest.raises(NetError, match="missing.example.com"):
        iplocation.run(ctx_for("domain", "missing.example.com", routes)[0])


def test_reverseip(monkeypatch):
    monkeypatch.setattr(reverseip, "ptr", lambda r, ip: ["host.example.com."])
    routes = {"https://internetdb.shodan.io/203.0.113.5": (200, {
        "ports": [22, 443], "hostnames": ["www.example.com"], "tags": ["cloud"],
        "cpes": ["cpe:/a:example:server"], "vulns": ["CVE-2099-0001"]}, None)}
    findings = reverseip.run(ctx_for("ip", "203.0.113.5", routes)[0])
    assert [f.value for f in findings if f.title == "Indexed open port"] == ["22/tcp", "443/tcp"]
    assert titles(findings)["PTR (reverse DNS)"] == "host.example.com"
    assert "Never test" in next(f.notes for f in findings if f.title.startswith("Known CVEs"))

    routes = {"https://internetdb.shodan.io/": (404, {"detail": "No information available"}, None)}
    assert [f.title for f in reverseip.run(ctx_for("ip", "203.0.113.6", routes)[0])] == ["PTR (reverse DNS)"]


def test_subdomainscan():
    rows = [{"name_value": "example.com\n*.example.com\ndev.example.com"},
            {"name_value": "DEV.example.com\nmail.example.com\nevil-example.com\nexample.com.attacker.test"}]
    assert subdomainscan.names_from_crtsh(rows, "example.com") == ["dev.example.com", "mail.example.com"]
    routes = {"https://crt.sh/": (200, rows, None)}
    findings = subdomainscan.run(ctx_for("domain", "example.com", routes)[0])
    assert [f.value for f in findings] == ["dev.example.com", "mail.example.com"]
    assert all(f.result is ResultKind.FOUND for f in findings)


def test_header_analyzer_and_tech_detector():
    rows = headeranalyzer.analyze(200, "https://example.com/", {
        "server": "nginx", "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'"})
    missing = [title for title, _, kind in rows if kind is ResultKind.FOUND]
    assert "Missing: Strict-Transport-Security" not in missing
    assert "Missing: X-Frame-Options" not in missing  # covered by CSP frame-ancestors
    assert "Missing: X-Content-Type-Options" in missing

    html = ('<html><meta name="generator" content="WordPress 6.6"><script src="/wp-content/x.js"></script>'
            '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script></html>')
    techs = dict(techdetector.detect({"server": "nginx/1.25", "cf-ray": "abc", "set-cookie": "PHPSESSID=x"}, html))
    assert {"nginx", "Cloudflare (CDN)", "PHP", "WordPress", "jQuery", "WordPress 6.6"} <= set(techs)

    routes = {"https://example.com/": (200, html.encode(), {"server": "nginx", "content-type": "text/html"})}
    findings = techdetector.run(ctx_for("domain", "example.com", routes)[0])
    assert "Likely: WordPress" in titles(findings)
    findings = headeranalyzer.run(ctx_for("domain", "example.com", routes)[0])
    assert titles(findings)["Header server"] == "nginx"


def test_githubrecon():
    seen = []
    api = githubrecon.API
    routes = {
        f"{api}/users/example_user/repos": (200, [
            {"name": "dotfiles", "full_name": "example_user/dotfiles", "description": "My config",
             "html_url": "https://github.com/example_user/dotfiles", "pushed_at": "2026-10-01T00:00:00Z", "fork": False},
            {"name": "forked", "fork": True}], None),
        f"{api}/users/example_user/events/public": (200, [
            {"type": "PushEvent", "created_at": "2026-10-28T10:00:00Z"},
            {"type": "PushEvent", "created_at": "2026-10-20T10:00:00Z"}], None),
        f"{api}/users/example_user": (200, {"html_url": "https://github.com/example_user", "name": "Example User",
                                            "public_repos": 1, "followers": 0, "created_at": "2020-01-01"}, None),
    }
    findings = githubrecon.run(ctx_for("username", "example_user", routes, api_key="ghp-example", seen=seen)[0])
    found = titles(findings)
    assert found["GitHub profile"] == "https://github.com/example_user"
    assert found["Repository dotfiles"].startswith("My config")
    assert "Repository forked" not in found
    assert found["Recent public activity"] == "2 Push · latest 2026-10-28"
    assert seen[0].headers["authorization"] == "Bearer ghp-example"
    profile = next(f for f in findings if f.title == "GitHub profile")
    assert profile.result is ResultKind.FOUND and "not proof" in profile.notes

    routes = {f"{api}/users/": (404, {"message": "Not Found"}, None)}
    assert [f.title for f in githubrecon.run(ctx_for("username", "nobody_example", routes)[0])] == ["No GitHub account"]


def test_breachchecker():
    with pytest.raises(ValueError, match="API key"):
        breachchecker.run(ctx_for("email", "owner@example.com")[0])
    seen = []
    breaches = [{"Name": "ExampleBreach", "Title": "Example Breach", "BreachDate": "2020-01-01",
                 "DataClasses": ["Email addresses", "Passwords"], "Password": "hunter2"}]
    routes = {"https://haveibeenpwned.com/api/v3/breachedaccount/owner@example.com": (200, breaches, None)}
    [finding] = breachchecker.run(ctx_for("email", "owner@example.com", routes, api_key="hibp-example", seen=seen)[0])
    assert finding.title == "Breach: Example Breach"
    assert "hunter2" not in finding.model_dump_json()  # passwords are never stored
    assert seen[0].headers["hibp-api-key"] == "hibp-example"
    routes = {"https://haveibeenpwned.com/": (404, b"", None)}
    [none] = breachchecker.run(ctx_for("email", "owner@example.com", routes, api_key="hibp-example")[0])
    assert none.title == "No known breaches"


def test_blackbird_parse():
    lines = ["🛰️  Enumerating accounts with email \"owner@example.com\" — 100% (90/90)",
             "  ✔️  [GitHub] https://github.com/example_user",
             "  ✔️  [Gravatar] https://en.gravatar.com/example_user",
             "  ✔️  [GitHub] https://github.com/example_user",
             ":chequered_flag: Check completed in 12.3 seconds (90 sites)"]
    result = blackbird.parse(lines)
    assert [f.title for f in result.findings] == ["GitHub account", "Gravatar account"]
    assert result.counts == {"found": 2, "checked": 90}
    assert blackbird.console_tag(lines[1]) == "g"


# ---------------------------------------------------------------- core.net


def test_http_errors_and_size_limit(monkeypatch):
    for status, text in ((401, "API key"), (429, "rate-limited"), (503, "server error")):
        ctx, _ = ctx_for("domain", "example.com", {"https://example.com/": (status, b"", None)})
        with pytest.raises(NetError, match=text):
            ctx.http().request("web", "https://example.com/")
    monkeypatch.setattr(net, "MAX_RESPONSE_BYTES", 1000)
    ctx, _ = ctx_for("domain", "example.com", {"https://example.com/": (200, b"x" * 5000, None)})
    with pytest.raises(NetError, match="more than"):
        ctx.http().request("web", "https://example.com/")
    with pytest.raises(NetError, match="Only http"):
        ctx.http().request("web", "file:///C:/Windows/win.ini")


def test_cache_avoids_repeat_queries(tmp_path):
    db = Database(tmp_path / "cache.db")
    seen = []
    routes = {"https://internetdb.shodan.io/203.0.113.5": (200, {"ports": [80]}, None)}
    cache = ApiCache(db.path, enabled=True)
    for _ in range(2):
        ctx, _ = ctx_for("ip", "203.0.113.5", routes, cache=cache, seen=seen)
        assert ctx.http().get_json("internetdb", "https://internetdb.shodan.io/203.0.113.5") == {"ports": [80]}
    assert len(seen) == 1
    db.close()


def test_rate_limit_spaces_requests(monkeypatch):
    monkeypatch.setattr(net, "RATE_LIMITS", {"slow": 0.3})
    ctx, _ = ctx_for("domain", "example.com", {"https://example.com/": (200, b"ok", None)})
    http = ctx.http()
    start = time.monotonic()
    http.request("slow", "https://example.com/")
    http.request("slow", "https://example.com/")
    assert time.monotonic() - start >= 0.28


def test_cancel_interrupts_waiting():
    ctx, _ = ctx_for("domain", "example.com", {"https://example.com/": (200, b"ok", None)})
    ctx._cancel.set()
    with pytest.raises(JobCancelled):
        ctx.http().request("web", "https://example.com/")


def test_accountinfo_reads_only_real_profile_pages():
    from adapters.accountinfo import profile

    page = ('<meta property="og:title" content="Example (@example_user)">'
            '<meta property="og:description" content="1,234 Followers, 5 Following, 6 Posts &#x2022; hello">')
    assert profile(page, " Followers", "description") == ("Example (@example_user)",
                                                          "1,234 Followers, 5 Following, 6 Posts \u2022 hello")
    login_wall = '<meta property="og:title" content="Log in"><p>Followers</p>'
    assert profile(login_wall, " Followers", "description") is None
    assert profile("<html>no such user</html>", "tgme_page_title", None) is None


def test_maigret_account_facts_are_separate_findings(tmp_path):
    import json

    from adapters.maigret import parse
    from core.findings import ResultKind

    report = {"Twitter": {"url_user": "https://x.com/example_user",
                          "status": {"ids": {"created_at": "2015-01-02", "follower_count": 3, "image": "skip"}}}}
    (tmp_path / "report_example_user_simple.json").write_text(json.dumps(report), encoding="utf-8")
    result = parse([], tmp_path, "example_user")
    assert result.counts == {"found": 1, "account_facts": 2}
    facts = {f.title: f.value for f in result.findings if f.result is ResultKind.INFO}
    assert facts == {"Twitter: account created": "2015-01-02", "Twitter: followers": "3"}


TIKTOK_PAGE = '''<html><script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">
{"__DEFAULT_SCOPE__": {"webapp.user-detail": {"userInfo": {
  "user": {"id": "7474765352946254853", "uniqueId": "example_user", "nickname": "Example", "signature": "",
           "createTime": 0, "nickNameModifyTime": 1772594266, "uniqueIdModifyTime": 0, "secret": true,
           "avatarLarger": "https://example.com/a.jpg", "secUid": "x", "newField": 7,
           "profileTab": {"showMusicTab": false}},
  "stats": {"followerCount": 6, "followingCount": 78, "heart": 35, "heartCount": 35, "videoCount": 0}
}}}}</script></html>'''


def test_tiktokpage_shows_every_field_in_english():
    from adapters.tiktokpage import ESTIMATE, read_profile, rows

    shown = {title: (value, note) for title, value, note in rows(read_profile(TIKTOK_PAGE))}
    assert shown["Username"][0] == "example_user"
    assert shown["Followers"][0] == "6" and shown["Likes"][0] == "35"
    assert shown["Created"] == ("2025-02-23 23:47:08 UTC", ESTIMATE)
    assert shown["Username changed"][0] == "Never"
    assert shown["Name changed"][0] == "2026-03-04 03:17:46 UTC"
    assert shown["Secret account"][0] == "Yes" and shown["Music tab"][0] == "No"
    assert shown["Bio"][0] == "(empty)"
    assert shown["newField"][0] == "7"  # fields TikTok adds later are not lost
    assert not {"avatarLarger", "secUid", "heart"} & set(shown)


def test_tiktokpage_refuses_other_files():
    from adapters.tiktokpage import read_profile

    with pytest.raises(ValueError, match="saved TikTok profile page"):
        read_profile("<html>Please verify you are human</html>")


EMAIL = b"""Received: from mx.example.com (mx.example.com [203.0.113.9])
 by mail.example.net with ESMTPS; Mon, 2 Nov 2026 10:00:02 +0000
Received: from internal.example.com ([10.0.0.5]) by mx.example.com; Mon, 2 Nov 2026 10:00:01 +0000
Received: from sender.example.com (sender.example.com [192.0.2.50] (may be forged))
 by internal.example.com; Mon, 2 Nov 2026 10:00:00 +0000
Received: from desk ([8.8.4.4]) by sender.example.com; Mon, 2 Nov 2026 09:59:59 +0000
Authentication-Results: mail.example.net; spf=pass smtp.mailfrom=example.com; dkim=fail; dmarc=none
From: Example Owner <owner@example.com>
Reply-To: other@example.org
Return-Path: <bounce@mail.example.com>
Subject: Hello
Date: Mon, 2 Nov 2026 09:59:58 +0000

Body text that must not be read.
"""


def test_emailheaders_finds_the_first_public_server_and_mismatches():
    from adapters.emailheaders import analyze

    found = titles(analyze(EMAIL))
    assert found["Originating server IP"] == "8.8.4.4"  # the oldest hop with a public address
    assert (found["SPF"], found["DKIM"], found["DMARC"]) == ("pass", "fail", "none")
    assert found["Reply-To differs from From"] == "example.com / example.org"
    assert "Return-Path differs from From" not in found  # a subdomain of the sender is normal
    assert found["Hop 1"].startswith("from desk")
    assert "Body text" not in " ".join(found.values())


def test_emailheaders_refuses_other_files():
    from adapters.emailheaders import analyze

    with pytest.raises(ValueError, match="no email headers"):
        analyze(b"just some text")


def test_lookalike_skips_the_original_domain():
    from adapters.lookalike import parse

    lines = ["WARNING: something on stderr", "[", '{"domain": "example.com", "fuzzer": "*original"},',
             '{"domain": "examp1e.com", "fuzzer": "homoglyph", "dns_a": ["192.0.2.10"], "dns_mx": ["mx.examp1e.com"]}', "]"]
    result = parse(lines)
    assert [f.value for f in result.findings] == ["examp1e.com"]
    assert "homoglyph" in result.findings[0].notes and "A: 192.0.2.10" in result.findings[0].notes
    assert result.counts == {"found": 1}


def test_waybackhistory():
    from adapters import waybackhistory

    base = waybackhistory.API + "?url=example.com&output=json"
    routes = {
        base + "&fl=timestamp%2Coriginal&limit=1": (200, [["timestamp", "original"], ["19971210061738", "http://example.com/"]], None),
        base + "&fl=timestamp%2Coriginal&limit=-1": (200, [["timestamp", "original"], ["20261029063533", "https://example.com/"]], None),
        base + "&fl=timestamp&collapse=timestamp%3A4": (200, [["timestamp"], ["19971210061738"], ["20261029063533"]], None),
    }
    found = {f.title: f for f in waybackhistory.run(ctx_for("domain", "example.com", routes)[0])}
    assert found["First archived copy"].value == "1997-12-10"
    assert found["First archived copy"].url == "https://web.archive.org/web/19971210061738/http://example.com/"
    assert found["Years with copies (2)"].value == "1997, 2026"
    empty = {base + "&fl=timestamp%2Coriginal&limit=1": (200, [], None)}
    assert [f.title for f in waybackhistory.run(ctx_for("domain", "example.com", empty)[0])] == ["No archived copy"]


def test_videoinfo_reads_the_info_file(tmp_path):
    from adapters.videoinfo import parse

    (tmp_path / "video.info.json").write_text(json.dumps({
        "webpage_url": "https://video.example.com/1", "extractor": "example", "title": "A video",
        "uploader": "example_user", "timestamp": 1114313512, "view_count": 0, "description": "",
    }), encoding="utf-8")
    result = parse([], tmp_path, "https://video.example.com/1")
    found = titles(result.findings)
    assert found["Uploaded"] == "2005-04-24 03:31:52 UTC"
    assert found["Uploader"] == "example_user" and found["Views"] == "0" and "Description" not in found
    # No info file: yt-dlp's own error line is the reason, not a generic one.
    error = "ERROR: [generic] Unsupported URL: https://example.com/"
    with pytest.raises(ValueError, match="Unsupported URL"):
        parse(["WARNING: something", error], tmp_path / "missing", "https://example.com/")
    with pytest.raises(ValueError, match="no video details"):
        parse([], tmp_path / "missing", "https://example.com/")
    (tmp_path / "video.info.json").write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected output from yt-dlp"):
        parse([], tmp_path, "https://video.example.com/1")


def test_urlscan_searches_existing_scans_only():
    from adapters import urlscan

    seen = []
    routes = {urlscan.API + "?q=page.domain%3Aexample.com&size=10": (200, {"total": 41, "results": [{
        "task": {"time": "2026-10-30T12:45:24.839Z", "uuid": "abc"},
        "page": {"url": "https://example.com/", "ip": "192.0.2.10", "title": "Example", "country": "ZZ"},
    }]}, None)}
    findings = urlscan.run(ctx_for("url", "https://example.com/login", routes, seen=seen)[0])
    assert all(request.method == "GET" for request in seen)  # never submits a scan
    assert findings[0].title == "Scan on 2026-10-30"
    assert findings[0].url == "https://urlscan.io/result/abc/"
    assert "IP: 192.0.2.10" in findings[0].notes


def test_emailprofile_sends_a_hash_and_only_the_domain(monkeypatch):
    from adapters import emailprofile

    monkeypatch.setattr(emailprofile, "resolver", lambda: None)
    monkeypatch.setattr(emailprofile, "query", lambda r, name, rtype: {
        ("example.com", "MX"): ["10 mail.example.com."], ("example.com", "TXT"): ['"v=spf1 -all"', '"other"'],
        ("_dmarc.example.com", "TXT"): []}[(name, rtype)])
    seen = []
    routes = {
        emailprofile.gravatar_url("owner@example.com"): (200, {"entry": [{
            "displayName": "Example", "profileUrl": "https://gravatar.com/example_user",
            "accounts": [{"shortname": "github", "url": "https://github.com/example_user"}]}]}, None),
        "https://open.kickbox.com/v1/disposable/example.com": (200, {"disposable": False}, None),
    }
    found = titles(emailprofile.run(ctx_for("email", "owner@example.com", routes, seen=seen)[0]))
    assert found["Gravatar: Name"] == "Example"
    assert found["Linked account: github"] == "https://github.com/example_user"
    assert found["SPF record"] == '"v=spf1 -all"' and found["DMARC record"] == "None"
    assert found["Disposable mail domain"] == "No"
    assert not any("owner@example.com" in str(request.url) for request in seen)


def test_blackbird_usernames_belong_to_userrecon():
    from adapters.blackbird import parse_username

    result = parse_username(["\u2714\ufe0f  [Example] https://example.com/example_user"])
    assert [(f.module, f.url) for f in result.findings] == [("UserRecon", "https://example.com/example_user")]
    assert "Username match" in result.findings[0].notes
