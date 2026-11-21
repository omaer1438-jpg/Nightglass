"""Evidence hashing, report export with redaction, retention and case deletion."""

from __future__ import annotations

import csv
import io
from datetime import timedelta

import pytest

from core.evidence import EvidenceError, EvidenceStore
from core.findings import Finding, FindingStore, ResultKind
from core.reports import ReportError, ReportOptions, default_path, export, redact, render
from core.retention import delete_case, purge_expired
from core.runs import ConsentLog, RunStore, case_dir


@pytest.fixture
def case(manager, new_case):
    return manager.create_case(new_case())


@pytest.fixture
def populated(db, case, tmp_path):
    store = FindingStore(db)
    ids = store.add(case.id, [
        Finding(module="UserRecon", title="GitHub profile", source="Sherlock",
                url="https://github.com/example_user", notes="Contact owner@example.com"),
        Finding(module="UserRecon", title="Reddit profile", source="Sherlock",
                url="https://www.reddit.com/user/example_user"),
        Finding(module="PhoneIntel", title="International format", value="+1 555-010-0123", source="phonenumbers",
                result=ResultKind.INFO),
        Finding(module="EmailFootprint", title="Contact email", value="owner@example.com", source="Blackbird"),
        Finding(module="ReverseIP", title="=HYPERLINK(\"http://evil.example\")", value="203.0.113.5",
                source="Shodan InternetDB"),
    ])
    store.set_status(ids[0], "verified", "Bio links to example.com.")
    store.set_status(ids[1], "rejected", "Different person.")
    sample = tmp_path / "profile_01.png"
    sample.write_bytes(b"fake screenshot")
    EvidenceStore(db, tmp_path / "data").add(case.id, sample, "Screenshot of the profile")
    return ids


def test_evidence_is_copied_hashed_and_verifiable(db, case, tmp_path):
    store = EvidenceStore(db, tmp_path)
    source = tmp_path / "in" / "profile 01.png"
    source.parent.mkdir()
    source.write_bytes(b"fake screenshot")
    item = store.add(case.id, source, "Screenshot")
    assert len(item.sha256) == 64
    assert item.path.startswith(str(case_dir(case.id, tmp_path) / "evidence"))
    assert store.verify(item.id) is True
    with open(item.path, "ab") as handle:
        handle.write(b"tampered")
    assert store.verify(item.id) is False
    source.unlink()
    assert store.verify(item.id) is False  # the case copy is what matters, not the original
    with pytest.raises(EvidenceError, match="exists"):
        store.add(case.id, tmp_path / "missing.png")


def test_re_adding_never_touches_stored_evidence(db, case, tmp_path):
    store = EvidenceStore(db, tmp_path)
    source = tmp_path / "profile.png"
    source.write_bytes(b"fake screenshot")
    first = store.add(case.id, source)
    again = store.add(case.id, source)
    assert again.path == first.path  # an intact copy is reused
    with open(first.path, "ab") as handle:
        handle.write(b"tampered")
    third = store.add(case.id, source)
    assert third.path != first.path and store.verify(third.id) is True
    assert store.verify(first.id) is False  # the altered copy is still there for verify() to flag
    assert not list((case_dir(case.id, tmp_path) / "evidence").glob("*.part"))


def test_evidence_link_must_be_a_finding_of_the_same_case(db, case, manager, new_case, tmp_path):
    other = manager.create_case(new_case(name="Own domain audit"))
    finding_id = FindingStore(db).add(other.id, [Finding(module="UserRecon", title="GitHub profile",
                                                         source="Sherlock")])[0]
    sample = tmp_path / "a.png"
    sample.write_bytes(b"x")
    store = EvidenceStore(db, tmp_path)
    with pytest.raises(EvidenceError, match="finding"):
        store.add(case.id, sample, finding_id=finding_id)
    assert store.add(other.id, sample, finding_id=finding_id).finding_id == finding_id


def test_evidence_refused_on_closed_case(db, case, manager, tmp_path):
    manager.close_case(case.id)
    sample = tmp_path / "a.png"
    sample.write_bytes(b"x")
    with pytest.raises(EvidenceError, match="closed"):
        EvidenceStore(db, tmp_path).add(case.id, sample)


def test_redaction():
    opts = ReportOptions(redact_contacts=True, redact_ips=True)
    text = "Mail owner@example.com or +1 555 010 0123 from 192.0.2.10 / 2001:db8::1"
    assert redact(text, opts) == "Mail [redacted email] or [redacted phone] from [redacted IP] / [redacted IP]"
    assert redact(text, ReportOptions(redact_contacts=False, redact_ips=False)) == text


def test_html_report_sections_and_redaction(db, case, populated):
    html = render(db, case.id, ReportOptions(fmt="html"))
    assert "Verified findings" in html and "Leads — not verified" in html
    assert "<h2>Rejected</h2>" not in html
    assert "owner@example.com" not in html and "[redacted email]" in html
    assert "+1 555-010-0123" not in html
    assert "SHA-256" in html and "Limitations" in html
    assert "not proof of identity" in html
    assert "<script" not in html.lower()


def test_markdown_and_options(db, case, populated):
    md = render(db, case.id, ReportOptions(fmt="md", include_rejected=True, include_limitations=False,
                                           include_info=False, redact_contacts=False))
    assert "## Rejected" in md and "Reddit profile" in md
    assert "## Limitations" not in md
    assert "International format" not in md
    assert "owner@example.com" in md


def test_csv_blocks_formula_injection(db, case, populated):
    content = render(db, case.id, ReportOptions(fmt="csv", redact_ips=True))
    rows = list(csv.DictReader(io.StringIO(content)))
    titles = [r["title"] for r in rows]
    assert "'=HYPERLINK(\"http://evil.example\")" in titles
    assert all(r["value"] != "203.0.113.5" for r in rows)
    assert {r["status"] for r in rows} >= {"Verified", "Lead — not verified"}


def test_export_writes_file_and_reports_failures(db, case, populated, tmp_path):
    path = export(db, case.id, ReportOptions(fmt="html"), tmp_path / "out" / "report.html")
    assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    blocker = tmp_path / "file_not_folder"
    blocker.write_text("x")
    with pytest.raises(ReportError, match="Could not save"):
        export(db, case.id, ReportOptions(fmt="md"), blocker / "report.md")
    assert default_path(case.id, case.ref, "csv", tmp_path).name.startswith("CASE-001-report-")


def test_delete_case_removes_everything(db, case, populated, tmp_path):
    RunStore(db, tmp_path / "data").create(case.id, "UserRecon")
    ConsentLog(db).record(case.id, "UserRecon", "sites", "example_user", scope_confirmed=True)
    ConsentLog(db).remember(case.id, "userrecon")
    db.set_setting("last_case_id", case.id)
    folder = case_dir(case.id, tmp_path / "data")
    assert folder.exists()
    assert delete_case(db, case.id, tmp_path / "data") == "CASE-001"
    for table in ("cases", "targets", "findings", "evidence", "runs", "consents"):
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    assert not folder.exists()
    assert db.get_setting("last_case_id") is None
    assert db.get_setting(f"consent.remember.{case.id}.userrecon") is None


def test_retention_purges_only_expired_closed_cases(db, manager, new_case, clock, tmp_path):
    keep_open = manager.create_case(new_case(name="Open"))
    old = manager.create_case(new_case(name="Old"))
    recent = manager.create_case(new_case(name="Recent"))
    forever = manager.create_case(new_case(name="Forever"))
    manager.close_case(old.id)
    clock.advance(days=80)
    manager.close_case(recent.id)
    manager.close_case(forever.id)
    db.execute("UPDATE cases SET retention_days = NULL WHERE id = ?", (forever.id,))
    removed = purge_expired(db, now=clock.now + timedelta(days=11), root=tmp_path)
    assert removed == ["CASE-002"]
    assert {c.name for c in manager.list_cases()} == {"Open", "Recent", "Forever"}
    assert manager.get_case(keep_open.id).is_open
