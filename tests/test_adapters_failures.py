"""Failure paths of the adapters (audit M4, M6, M7, M8): unreachable sources, 429/5xx, malformed or
oversized output and wrapped console output. Mocked network only; fake data only."""

from __future__ import annotations

import json

import dns.exception
import dns.resolver
import pytest

from adapters import (
    accountinfo, blackbird, breachchecker, dnsrecon, emailprofile, githubrecon, headeranalyzer, iplocation, lookalike,
    maigret, rdap, reverseip, sherlock, socialanalyzer, subdomainscan, subfinder, techdetector, theharvester, urlscan,
    videoinfo, waybackhistory,
)
from core.findings import ResultKind
from core.net import NetError
from tests.test_adapters_net import ctx_for, no_rate_limits  # noqa: F401  (autouse fixture)

OK = "✔️"

# Real Blackbird 2.x output, piped (rich wraps at 80 columns). Values not about the fake target were replaced.
BLACKBIRD_EMAIL = f"""\
⏭  Skipping update...
  {OK}  [Spotify]
https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=user@
example.com
  {OK}  [Chess.com]
https://www.chess.com/callback/email/available?email=user@example.com
  {OK}  [Twitter]
https://api.twitter.com/i/users/email_available.json?email=user@example.com
  {OK}  [Gravatar]
https://gravatar.com/b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e
475514.json
      ➡  Avatar:
https://0.gravatar.com/avatar/b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e
1cc1ffc5e475514
      ➡  Name: example_user
  {OK}  [El Mundo] https://seguro.elmundo.es/ueregistro/v2/usuarios/registro
  {OK}  [Duolingo]
https://www.duolingo.com/2017-06-30/users?email=user@example.com
  {OK}  [Adobe] https://auth.services.adobe.com/signin/v2/users/accounts
      ➡  Avatar:
https://pps.services.adobe.com/api/profile/image/default/00000000-0000-0000-000
0-000000000000/230
  {OK}  [Eventbrite] https://www.eventbrite.com/api/v3/users/lookup/
      ➡  User ID: 000000000000
🛰️  Enumerating accounts with email "user@example.com" — 100% (16/16)🏁 Check completed in 20.7 seconds (16 sites)
""".splitlines()

BLACKBIRD_USERNAME = f"""\
  {OK}  [Instagram] https://www.instagram.com/example_user/
  {OK}  [Aparat]
https://www.aparat.com/api/fa/v1/user/user/information/username/example_user
  {OK}  [StackOverflow]
https://api.stackexchange.com/2.3/users?order=desc&sort=name&inname=example_use
r&site=stackoverflow
  {OK}  [Disqus]
https://disqus.com/api/3.0/users/details?user=username:example_user&api_key=EXA
MPLEKEY
  {OK}  [TikTok]
https://www.tiktok.com/oembed?url=https://www.tiktok.com/@example_user
      ➡  Name: example_user
  {OK}  [HudsonRock]
https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?user
name=example_user
  {OK}  [Roblox]
https://auth.roblox.com/v1/usernames/validate?username=example_user&birthday=20
19-12-31T23:00:00.000Z
  {OK}  [Telegram] https://t.me/example_user
🛰️  Enumerating accounts with username "example_user" — 100% (692/692)🏁 Check completed in 37.4 seconds
""".splitlines()


# ---------------------------------------------------------------- M4: Blackbird wrapped lines


def test_blackbird_keeps_every_wrapped_hit():
    result = blackbird.parse(BLACKBIRD_EMAIL)
    urls = {f.title: f.url for f in result.findings}
    assert len(urls) == 8 and result.counts == {"found": 8, "checked": 16}
    assert urls["Spotify account"] == ("https://spclient.wg.spotify.com/signup/public/v1/account"
                                       "?validate=1&email=user@example.com")
    assert urls["Gravatar account"].endswith("1ffc5e475514.json")  # the avatar link is not glued on
    assert urls["Eventbrite account"] == "https://www.eventbrite.com/api/v3/users/lookup/"


def test_blackbird_username_wrapped_urls_are_joined():
    urls = {f.title: f.url for f in blackbird.parse_username(BLACKBIRD_USERNAME).findings}
    assert len(urls) == 8
    assert urls["StackOverflow account"].endswith("inname=example_user&site=stackoverflow")
    assert urls["HudsonRock account"].endswith("search-by-username?username=example_user")
    assert urls["Roblox account"].endswith("birthday=2019-12-31T23:00:00.000Z")
    assert urls["TikTok account"] == "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@example_user"


def test_blackbird_wide_console_still_parses():
    wide = [f"  {OK}  [Spotify] https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=user@example.com"]
    assert [f.url for f in blackbird.parse(wide).findings] == [wide[0].split()[-1]]


# ---------------------------------------------------------------- M7: Sherlock offline


def test_sherlock_offline_fails_instead_of_flooding():
    lines = ["[*] Checking username example_user on:"] + [f"[-] Site{i}: Proxy Error" for i in range(447)]
    lines += ["[-] 1337x: Illegal Username Format For This Site!", "[*] Search completed with 0 results"]
    with pytest.raises(ValueError, match="No site could be reached: 447 of 447"):
        sherlock.parse(lines)


def test_sherlock_mass_errors_keep_leads_and_cap_uncertain():
    lines = [f"[+] Example{i}: https://example.com/{i}/example_user" for i in range(3)]
    lines += [f"[-] Site{i}: Error Connecting" for i in range(300)] + ["[-] Other: Not Found!"]
    result = sherlock.parse(lines)
    kinds = [f.result for f in result.findings]
    assert kinds.count(ResultKind.FOUND) == 3 and kinds.count(ResultKind.UNCERTAIN) == sherlock.MAX_UNCERTAIN
    assert result.counts["uncertain"] == 300
    assert result.counts[f"uncertain_not_stored_(limit_{sherlock.MAX_UNCERTAIN})"] == 300 - sherlock.MAX_UNCERTAIN


def test_sherlock_short_or_normal_runs_are_not_failed():
    assert len(sherlock.parse([f"[-] Site{i}: Error Connecting" for i in range(5)]).findings) == 5  # cut-off run
    normal = [f"[+] Example{i}: https://example.com/{i}" for i in range(60)] + [f"[-] S{i}: Error" for i in range(60)]
    assert len(sherlock.parse(normal).findings) == 120


# ---------------------------------------------------------------- M8: oversized fields


def test_oversized_tool_output_is_cut_not_fatal(tmp_path):
    long_url = "https://example.com/" + "a" * 3000
    result = sherlock.parse(["[+] " + "S" * 400 + f": {long_url}", "[+] GitHub: https://github.com/example_user"])
    assert len(result.findings) == 2
    assert len(result.findings[0].title) == 300 and result.findings[0].url is None
    assert blackbird.parse([f"  {OK}  [Example] {long_url}"]).findings[0].value == long_url

    (tmp_path / "report_example_user_simple.json").write_text(json.dumps({"Example": {
        "url_user": long_url, "status": {"ids": {"fullname": "n" * 5000}}}}), encoding="utf-8")
    found = maigret.parse([], tmp_path, "example_user").findings
    assert [f.title for f in found] == ["Example profile", "Example: name"] and found[0].url is None


# ---------------------------------------------------------------- malformed tool output


@pytest.mark.parametrize("parser, lines, file, content", [
    (maigret.parse, [], "report_example_user_simple.json", "[1, 2]"),
    (maigret.parse, [], "report_example_user_simple.json", "{not json"),
    (maigret.parse, [], "report_example_user_simple.json", '{"Example": "x"}'),
    (socialanalyzer.parse, ["{garbage"], None, None),
    (socialanalyzer.parse, ['{"detected": "x"}'], None, None),
    (theharvester.parse, [], "report.json", "[1]"),
    (lookalike.parse, ["[1]"], None, None),
    (lookalike.parse, ['[{"domain": "examp1e.com"'], None, None),
    (videoinfo.parse, [], "video.info.json", "[]"),
])
def test_malformed_tool_output_gives_one_clear_error(tmp_path, parser, lines, file, content):
    if file:
        (tmp_path / file).write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="^Unexpected output from "):
        parser(lines, tmp_path, "example_user" if parser is maigret.parse else "example.com")


def test_lookalike_without_json():
    assert lookalike.parse([], None, "example.com").findings == []  # nothing registered: dnstwist prints nothing
    with pytest.raises(ValueError, match="dnstwist printed no results: usage: dnstwist"):
        lookalike.parse(["usage: dnstwist DOMAIN", "dnstwist: error: x"], None, "example.com")


def test_capped_counts_match_what_is_stored(monkeypatch):
    monkeypatch.setattr(subfinder, "MAX_NAMES", 2)
    lines = [json.dumps({"host": f"h{i}.example.com", "source": "crtsh"}) for i in range(5)]
    result = subfinder.parse(lines, None, "example.com")
    assert len(result.findings) == 2
    assert result.counts == {"found": 2, "found_not_stored_(over_2)": 3}


# ---------------------------------------------------------------- M6: unreachable, 429, 5xx


def test_accountinfo_all_sites_failing_is_a_failed_run():
    ctx, _ = ctx_for("username", "example_user", {"https://": (429, b"", None)})
    with pytest.raises(NetError, match="No site could be checked. Instagram rate-limited"):
        accountinfo.run(ctx)


def test_accountinfo_one_site_failing_is_marked_uncertain():
    page = b'<meta property="og:title" content="Example"><div class="tgme_page_title">Example</div>'
    routes = {"https://t.me/": (200, page, None), "https://": (503, b"", None)}
    findings = accountinfo.run(ctx_for("username", "example_user", routes)[0])
    uncertain = [f for f in findings if f.result is ResultKind.UNCERTAIN]
    assert [f.title for f in uncertain] == ["Instagram: not checked", "Threads: not checked"]
    assert "server error (503)" in uncertain[0].value
    assert "Telegram profile" in [f.title for f in findings]


def _dns_fails(r, name, rtype):
    raise dns.exception.Timeout()


def test_emailprofile_nothing_reachable_is_a_failed_run(monkeypatch):
    monkeypatch.setattr(emailprofile, "resolver", lambda: None)
    monkeypatch.setattr(emailprofile, "query", _dns_fails)
    ctx, _ = ctx_for("email", "owner@example.com", {"https://": (429, b"", None)})
    with pytest.raises(NetError, match="Nothing could be checked. gravatar rate-limited"):
        emailprofile.run(ctx)


def test_emailprofile_partial_failure_is_uncertain_not_silent(monkeypatch):
    monkeypatch.setattr(emailprofile, "resolver", lambda: None)
    monkeypatch.setattr(emailprofile, "query", lambda r, name, rtype: [])
    routes = {"https://gravatar.com/": (503, b"", None),
              "https://open.kickbox.com/": (200, {"disposable": False}, None)}
    ctx, lines = ctx_for("email", "owner@example.com", routes)
    findings = emailprofile.run(ctx)
    assert [f.title for f in findings if f.result is ResultKind.UNCERTAIN] == ["Gravatar: not checked"]
    assert "[-] no public Gravatar profile" not in lines  # unknown, not "none"


def test_dnsrecon_every_query_failing_is_a_failed_run(monkeypatch):
    monkeypatch.setattr(dnsrecon, "query", _dns_fails)
    with pytest.raises(NetError, match="No DNS answer: every query failed"):
        dnsrecon.run(ctx_for("domain", "example.com")[0])


def test_dnsrecon_partial_failure_is_uncertain(monkeypatch):
    def some(r, name, rtype):
        if rtype == "CAA":
            raise dns.resolver.NoNameservers()
        return ["192.0.2.10"] if rtype == "A" else []

    monkeypatch.setattr(dnsrecon, "query", some)
    findings = dnsrecon.run(ctx_for("domain", "example.com")[0])
    assert [(f.title, f.result) for f in findings] == [("A record", ResultKind.INFO),
                                                      ("DNS: not checked", ResultKind.UNCERTAIN)]
    assert findings[1].value == "No answer for: CAA NoNameservers"


def test_dns_query_reports_dead_resolvers_as_failure():
    class Dead:
        def resolve(self, *args, **kwargs):
            raise dns.resolver.NoNameservers()

    with pytest.raises(dns.exception.DNSException):
        dnsrecon.query(Dead(), "example.com", "A")
    assert dnsrecon.ptr(Dead(), "192.0.2.1") == []


@pytest.mark.parametrize("module", [headeranalyzer, techdetector])
@pytest.mark.parametrize("status, text", [(429, "rate-limited"), (503, "server error"), (404, "HTTP 404")])
def test_web_modules_never_analyse_an_error_page(module, status, text):
    routes = {"https://example.com/": (status, b"<html>Too Many Requests</html>", {"server": "nginx"})}
    with pytest.raises(NetError, match=f"example.com .*{text}"):
        module.run(ctx_for("domain", "example.com", routes)[0])


# ---------------------------------------------------------------- wrong-shape provider answers


@pytest.mark.parametrize("module, kind, target", [
    (iplocation, "ip", "192.0.2.1"), (rdap, "domain", "example.com"), (subdomainscan, "domain", "example.com"),
    (githubrecon, "username", "example_user"), (breachchecker, "email", "owner@example.com"),
    (reverseip, "ip", "192.0.2.1"), (waybackhistory, "domain", "example.com"), (urlscan, "domain", "example.com"),
    (emailprofile, "email", "owner@example.com"),
])
@pytest.mark.parametrize("body", [["x"], {"x": 1}, "text", 7])
def test_wrong_shape_answers_give_a_clean_error(monkeypatch, module, kind, target, body):
    monkeypatch.setattr(reverseip, "ptr", lambda r, ip: [])
    monkeypatch.setattr(emailprofile, "resolver", lambda: None)
    monkeypatch.setattr(emailprofile, "query", lambda r, name, rtype: [])
    ctx, _ = ctx_for(kind, target, {"https://": (200, body, None)}, api_key="key-example")
    try:
        module.run(ctx)
    except Exception as exc:  # noqa: BLE001 - the point is which exceptions get out
        assert type(exc) in (ValueError, NetError), f"{type(exc).__name__}: {exc}"
        assert type(exc) is NetError or str(exc).startswith("Unexpected output from ")
