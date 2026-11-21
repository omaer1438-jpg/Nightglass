"""Module engines (built-in vs. catalog tools) and the Maigret / Holehe / Subfinder / PhoneInfoga parsers."""

from __future__ import annotations

import json

import pytest

from adapters import holehe, maigret, phoneinfoga, subfinder
from core.catalog import load_catalog
from core.cases import LookupMode
from core.modules import check_gates, discover, engines, pick_engine
from core.secrets import KeyStore, MemoryKeyring
from core.validation import TargetType


def spec(module_id):
    return next(m for m in discover() if m.id == module_id)


def test_engines_use_tool_labels_and_switches(db):
    keys = KeyStore(MemoryKeyring())
    catalog = load_catalog()
    email = spec("emailfootprint")
    by_id = {e.id: e for e in engines(email, catalog, db, keys.has)}
    assert by_id["holehe"].is_active and by_id["holehe"].active_setting == "active.holehe"
    assert not by_id["holehe"].ready  # active tools stay off until enabled in Settings
    db.set_setting("active.holehe", True)
    holehe_engine = pick_engine(email, catalog, db, keys.has, "holehe")
    assert holehe_engine is not None and "active" in holehe_engine.labels

    phone = spec("phoneintel")
    built_in = pick_engine(phone, catalog, db, keys.has, "builtin")
    assert built_in.labels == ("local",) and not built_in.is_external
    tool = next(e for e in engines(phone, catalog, db, keys.has) if e.id == "phoneinfoga")
    assert tool.is_external  # same module, different engine -> consent needed


def test_holehe_engine_gets_full_active_gates(manager, new_case, db):
    db.set_setting("active.holehe", True)
    email = spec("emailfootprint")
    holehe_engine = next(e for e in engines(email, load_catalog(), db, KeyStore(MemoryKeyring()).has)
                         if e.id == "holehe")
    passive_case = manager.create_case(new_case(first_target_type=None, first_target_value=""))
    problems = check_gates(email, passive_case, TargetType.EMAIL, "owner@example.com", db, holehe_engine)
    assert any("does not allow active" in p for p in problems)
    assert any("not named" in p for p in problems)

    active_case = manager.create_case(new_case(authorized_scope="My own mailbox owner@example.com",
                                               allowed_modes=[LookupMode.LOCAL, LookupMode.ACTIVE],
                                               first_target_type=None, first_target_value=""))
    assert check_gates(email, active_case, TargetType.EMAIL, "owner@example.com", db, holehe_engine) == []
    db.set_setting("active.holehe", False)
    assert any("Settings" in p for p in
               check_gates(email, active_case, TargetType.EMAIL, "owner@example.com", db, holehe_engine))


def test_maigret_reads_json_report(tmp_path):
    report = tmp_path / "report_example_user_simple.json"
    report.write_text(json.dumps({
        "GitHub": {"url_user": "https://github.com/example_user",
                   "status": {"status": "Claimed", "ids": {"fullname": "Example User"}}},
        "Reddit": {"status": {"status": "Claimed", "url": "https://www.reddit.com/user/example_user"}},
    }), encoding="utf-8")
    result = maigret.parse([], tmp_path, "example_user")
    assert [(f.title, f.url) for f in result.findings] == [
        ("GitHub profile", "https://github.com/example_user"),
        ("GitHub: name", None),
        ("Reddit profile", "https://www.reddit.com/user/example_user"),
    ]
    assert "fullname: Example User" in result.findings[0].notes
    fallback = maigret.parse(["[+] GitLab: https://gitlab.com/example_user"], tmp_path / "missing", "example_user")
    assert [f.url for f in fallback.findings] == ["https://gitlab.com/example_user"]


def test_holehe_parse():
    lines = ["*************************", "   owner@example.com", "[+] example.com ex****@example.com",
             "[+] instagram.com", "[x] twitter.com", "[+] instagram.com",
             "121 websites checked in 9.7 seconds"]
    result = holehe.parse(lines)
    assert [f.title for f in result.findings] == ["Account on example.com", "Account on instagram.com"]
    assert "Partial recovery hints: ex****@example.com" in result.findings[0].notes
    assert result.counts == {"found": 2, "rate_limited": 1, "checked": 121}


def test_subfinder_parse_keeps_only_target_subdomains():
    lines = ['{"host":"dev.example.com","source":"crtsh"}', '{"host":"dev.example.com","source":"dnsdumpster"}',
             '{"host":"evil-example.com","source":"x"}', "mail.example.com", "not a host"]
    result = subfinder.parse(lines, None, "example.com")
    assert [f.value for f in result.findings] == ["dev.example.com", "mail.example.com"]
    assert "crtsh, dnsdumpster" in result.findings[0].notes


def test_phoneinfoga_parse():
    lines = ["Running scan for phone number +15550100123...", "", "Results for local", "Raw local: 5550100123",
             "E164: +15550100123", "", "Results for googlesearch", "Social media:",
             "\tURL: https://www.google.com/search?q=example", "1 scanner(s) succeeded"]
    result = phoneinfoga.parse(lines)
    titles = [f.title for f in result.findings]
    assert "E164 (local)" in titles and "Search link: Social media" in titles
    assert result.counts == {"scanners": 2, "facts": 2, "links": 1}


def test_theharvester_reads_its_report(tmp_path):
    from adapters import theharvester

    (tmp_path / "report.json").write_text(json.dumps({
        "hosts": ["www.example.com:192.0.2.10", "mail.example.com", "*.example.com:192.0.2.11", "other.test"],
        "emails": ["Owner@example.com"],
    }), encoding="utf-8")
    result = theharvester.parse([], tmp_path, "example.com")
    assert [f.value for f in result.findings] == ["mail.example.com", "www.example.com", "owner@example.com"]
    assert result.counts == {"found": 2, "emails": 1}
    assert theharvester.parse([], tmp_path / "missing", "example.com").findings == []


def test_spiderfoot_reads_each_line_even_when_cut_short():
    from adapters import spiderfoot

    event = '{{"generated": 1, "type": "{}", "data": "{}", "module": "sfp_crt", "source": "example.com"}}'
    lines = ["[--- Logging error ---", event.format("Internet Name", "www.example.com") + ",",
             event.format("Email Address", "owner@example.com") + "Traceback (most recent call last):",
             event.format("Internet Name", "unrelated.test") + ",",
             '{"generated": 2, "type": "Inter']
    result = spiderfoot.parse(lines, None, "example.com")
    assert [f.value for f in result.findings] == ["www.example.com", "owner@example.com"]
    assert "sfp_crt" in result.findings[0].notes


def test_own_home_keeps_tool_data_in_the_run_folder():
    from core.catalog import load_catalog

    catalog = load_catalog()
    assert catalog.get("theharvester").launch.own_home and catalog.get("spiderfoot").launch.own_home
    assert not catalog.get("sherlock").launch.own_home


def test_socialanalyzer_reads_the_json_line_after_warnings():
    from adapters import socialanalyzer

    lines = ["Some characters could not be decoded", json.dumps({"detected": [
        {"link": "https://www.example.com/example_user", "rate": "%100.0", "title": "Example"},
        {"link": "https://example.org/example_user", "rate": "%66.67", "title": "filtered"},
        {"link": "not a link", "rate": "%100.0"}], "failed": [{"link": "https://example.net/x"}]})]
    result = socialanalyzer.parse(lines)
    assert [(f.title, f.confidence.value) for f in result.findings] == [
        ("example.com profile", "medium"), ("example.org profile", "low")]
    assert "66.67%" in result.findings[1].notes and result.counts == {"found": 2}
    assert socialanalyzer.parse(["only warnings"]).findings == []


def test_wafdetect_reads_its_report(tmp_path):
    from adapters import wafdetect

    report = tmp_path / "waf.json"
    report.write_text(json.dumps([{"url": "https://example.com", "detected": True, "firewall": "Example WAF",
                                   "manufacturer": "Example Inc"}]), encoding="utf-8")
    assert [f.value for f in wafdetect.parse([], tmp_path, "https://example.com").findings] == ["Example WAF (Example Inc)"]
    report.write_text(json.dumps([{"url": "https://example.com", "detected": False}]), encoding="utf-8")
    assert wafdetect.parse([], tmp_path, "https://example.com").findings[0].title == "No firewall identified"
    report.write_text("[]", encoding="utf-8")
    down = ["ERROR:wafw00f:Site example.com appears to be down"]
    assert wafdetect.parse(down, tmp_path, "https://example.com").findings[0].title == "Site not reachable"
    # A crash or a stopped run is not "not reachable": the run fails with the real reason.
    report.unlink()
    with pytest.raises(ValueError, match="wafw00f wrote no results"):
        wafdetect.parse(["Traceback (most recent call last):", "ModuleNotFoundError: x"], tmp_path, "https://example.com")
    report.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected output from wafw00f"):
        wafdetect.parse([], tmp_path, "https://example.com")
    report.write_text("[{", encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected output from wafw00f: it is not valid JSON"):
        wafdetect.parse([], tmp_path, "https://example.com")


def test_zonetransfer_tells_open_from_closed():
    from adapters import zonetransfer

    closed = zonetransfer.parse(["[*] Trying NS server 192.0.2.53", "[-] Zone Transfer Failed (Zone transfer error: REFUSED)"])
    assert [f.title for f in closed.findings] == ["Zone transfer refused"]
    assert closed.findings[0].value == "0 of 1 name servers"

    # Offline / no such domain / crash: no server was tried, so no "safe setting" all-clear.
    for output in ([], ["[-] Could not resolve the NS records for example.com"], ["Traceback (most recent call last):"]):
        [head] = zonetransfer.parse(output, None, "example.com").findings
        assert head.title == "No name server could be checked" and head.result.value == "uncertain"

    opened = zonetransfer.parse(["[*] Trying NS server 192.0.2.53", "[+] 192.0.2.53 Has port 53 TCP Open",
                                 "[+] Zone Transfer was successful!!", "[*] \t A www.example.com 192.0.2.10",
                                 "[*] \t TXT ; ls", "[*] Trying NS server 192.0.2.54",
                                 "[+] Zone Transfer was successful!!", "[*] \t A www.example.com 192.0.2.10"])
    assert opened.counts == {"found": 2, "records": 2}
    assert [(f.title, f.value) for f in opened.findings[1:]] == [("Zone record A", "www.example.com 192.0.2.10"),
                                                                ("Zone record TXT", "; ls")]


def test_active_modules_are_off_until_enabled():
    from core.catalog import availability, load_catalog

    catalog = load_catalog()
    assert catalog.get("wafw00f").is_active and catalog.get("dnsrecon_axfr").is_active
    assert availability(catalog.get("wafw00f")).status == "Disabled"
    assert availability(catalog.get("dnsrecon_axfr")).status == "Disabled"
