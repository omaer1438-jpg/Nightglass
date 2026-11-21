"""Report completeness and trust: every section, redaction everywhere, CSV safety, integrity sidecar.
Fake data only."""

from __future__ import annotations

import csv
import hashlib
import io
from datetime import datetime, timezone

import pytest

from core.casemap import add_link
from core.evidence import EvidenceStore
from core.findings import Finding, FindingStore, ResultKind
from core.reports import ReportOptions, export, render, sidecar
from core.runs import ConsentLog, RunStore

LEGACY_DESC = r"Added from C:\Users\example_user\Downloads\profile 01.png"


@pytest.fixture
def case(manager, new_case, db, tmp_path):
    case = manager.create_case(new_case())
    manager.add_target(case.id, "email", "owner@example.com")
    runs = RunStore(db, tmp_path / "data")
    ok = runs.create(case.id, "EmailFootprint", external=True)
    runs.finish(ok.id, "succeeded")
    runs.finish(runs.create(case.id, "UserRecon").id, "failed")
    runs.finish(runs.create(case.id, "PortScan", active=True).id, "timed_out")
    ConsentLog(db).record(case.id, "EmailFootprint", "Gravatar", "owner@example.com", run_id=ok.id,
                          scope_confirmed=True)
    store = FindingStore(db)
    ids = store.add(case.id, [
        Finding(module="EmailFootprint", title="Gravatar profile", source="Gravatar",
                url="https://gravatar.com/example_user", notes="Mail owner@example.com"),
        Finding(module="EmailFootprint", title="Blocked lookup", source="Gravatar", result=ResultKind.UNCERTAIN),
        Finding(module="PhoneIntel", title="Number", value="+1 555-010-0123", source="phonenumbers",
                result=ResultKind.INFO),
        Finding(module="ReverseIP", title="@SUM(1)", value="203.0.113.5", source="Shodan InternetDB"),
        Finding(module="UserRecon", title="Old forum account", source="Sherlock",
                url="https://forum.example.com/u/example_user"),
    ], run_id=ok.id)
    store.set_status(ids[0], "verified", "Bio links to example.com.")
    store.set_status(ids[4], "rejected", "Different person.")
    sample = tmp_path / "owner@example.com.png"
    sample.write_bytes(b"fake screenshot")
    evidence = EvidenceStore(db, tmp_path / "data")
    stored, digest = evidence.copy_in(case.id, sample)
    evidence.record(case.id, stored, digest, LEGACY_DESC, ids[0])
    return case, ids


def test_html_has_every_section(db, case):
    case, _ = case
    html = render(db, case.id, ReportOptions(fmt="html"), checks=(datetime.now(timezone.utc), {}))
    for heading in ("Targets", "Verified findings", "Leads — not verified", "Uncertain — not verified",
                    "Info (descriptive data) — not verified", "Sources", "Consents", "Evidence (SHA-256)",
                    "Limitations"):
        assert f"<h2>{heading}</h2>" in html, heading
    assert "<h2>Rejected</h2>" not in html and "Old forum account" not in html
    for fact in ("CASE-001", "Authorized scope", "Created (UTC)", "Closed (UTC)", "Report generated",
                 "Nightglass version"):
        assert fact in html
    assert "Lead — not verified" in html and "Bio links to example.com." in html
    assert "r-0001" in html and "Timed out" in html and "Gravatar" in html
    assert "UserRecon (r-0002, failed); PortScan (r-0003, timed out)" in html
    assert "Hash re-check" in html and "Not checked" in html
    assert "<meta name='referrer' content='no-referrer'>" in html and "<script" not in html.lower()


def test_redaction_reaches_every_section_and_format(db, case):
    case, _ = case
    opts = dict(redact_contacts=True, redact_ips=True, include_rejected=True)
    for fmt in ("html", "md", "csv"):
        text = render(db, case.id, ReportOptions(fmt=fmt, **opts))
        assert "owner@example.com" not in text, fmt          # target, consent data, notes, evidence name
        assert "555-010-0123" not in text and "203.0.113.5" not in text, fmt
    md = render(db, case.id, ReportOptions(fmt="md", **opts))
    consents = md.split("## Consents")[1].split("##")[0]
    assert "Gravatar" in consents and "[redacted email]" in consents
    targets = md.split("## Targets")[1].split("##")[0]
    assert "| email | [redacted email] |" in targets


def test_csv_columns_and_formula_guard(db, case):
    case, ids = case
    rows = list(csv.DictReader(io.StringIO(render(db, case.id, ReportOptions(fmt="csv", redact_ips=True)))))
    assert set(rows[0]) == {"finding_id", "title", "value", "url", "module", "source", "collected_at_utc",
                            "confidence", "status", "verification_notes", "run_id"}
    by_id = {int(r["finding_id"]): r for r in rows}
    assert by_id[ids[3]]["title"] == "'@SUM(1)"
    assert by_id[ids[2]]["value"] == "[redacted phone]"
    assert by_id[ids[1]]["status"] == "Uncertain — not verified"
    assert by_id[ids[0]]["status"] == "Verified" and by_id[ids[0]]["run_id"] == "1"


def test_evidence_never_shows_a_local_path(db, case, tmp_path):
    case, _ = case
    name = EvidenceStore(db).list(case.id)[0].name
    for fmt in ("html", "md"):
        text = render(db, case.id, ReportOptions(fmt=fmt, redact_contacts=False))
        assert str(tmp_path) not in text and "Downloads" not in text and "C:\\" not in text
        assert "Added from profile 01.png" in text and name in text
        assert "Gravatar profile" in text.split("Evidence (SHA-256)")[1]  # linked finding


def test_hash_recheck_column(db, case):
    case, _ = case
    item = EvidenceStore(db).list(case.id)[0]
    md = render(db, case.id, ReportOptions(fmt="md"), checks=(datetime(2026, 11, 1, tzinfo=timezone.utc),
                                                              {item.id: False}))
    assert "CHANGED" in md and "2026-11-01 00:00:00 UTC" in md
    assert "Hash re-check" not in render(db, case.id, ReportOptions(fmt="md"))


def test_sha256_sidecar_matches(db, case, tmp_path):
    case, _ = case
    for fmt in ("html", "md", "csv"):
        path = export(db, case.id, ReportOptions(fmt=fmt), tmp_path / "out" / f"report.{fmt}")
        digest, name = sidecar(path).read_text(encoding="utf-8").split()
        assert name == path.name and digest == hashlib.sha256(path.read_bytes()).hexdigest()


def test_board_links_follow_include_options(db, case):
    case, ids = case
    add_link(db, case.id, "t:1", f"f:{ids[4]}", "same avatar as owner@example.com")
    add_link(db, case.id, "t:1", "s:Gravatar", "checked via")
    add_link(db, case.id, "t:1", f"f:{ids[1]}", "retry later")
    hidden = render(db, case.id, ReportOptions(fmt="md", include_sources=False))
    assert "same avatar" not in hidden and "checked via" not in hidden and "retry later" in hidden
    shown = render(db, case.id, ReportOptions(fmt="md", include_rejected=True))
    assert "Old forum account" in shown and "checked via" in shown
    assert "owner@example.com" not in shown.split("## Analyst notes and links")[1].split("##")[0]


def test_screen_rechecks_evidence_off_thread_and_shows_report_hash(qtbot, themed_app, db_path, new_case, tmp_path):
    from app.main_window import MainWindow
    from app.state import AppState
    from core.db import Database

    db = Database(db_path)
    state = AppState(db)
    window = MainWindow(state, str(db_path.parent))
    qtbot.addWidget(window)
    try:
        case = state.cases.create_case(new_case())
        sample = tmp_path / "profile.png"
        sample.write_bytes(b"fake screenshot")
        state.evidence.add(case.id, sample, "Screenshot")
        state.open_case(case.id)
        window.navigate("reports")
        screen = window.screens["reports"]
        qtbot.waitUntil(lambda: "Matches" in screen.preview.toPlainText(), timeout=5000)
        saved = screen.export()
        digest = hashlib.sha256(saved.read_bytes()).hexdigest()
        assert digest in screen.integrity.text() and digest in sidecar(saved).read_text(encoding="utf-8")
        assert "Matches" in saved.read_text(encoding="utf-8")
    finally:
        window.close()
        db.close()


def test_file_targets_show_only_the_file_name(manager, new_case, db, tmp_path):
    from core.casemap import build_graph

    photo = tmp_path / "private_folder" / "fake_photo.jpg"
    photo.parent.mkdir()
    photo.write_bytes(b"\xff\xd8\xff\xd9")
    case = manager.create_case(new_case())
    target = manager.add_target(case.id, "file", str(photo))
    for fmt in ("html", "md", "csv"):
        assert "private_folder" not in render(db, case.id, ReportOptions(fmt=fmt))
    node = build_graph(db, case.id).nodes[f"t:{target.id}"]
    assert node.label == node.value == "fake_photo.jpg"
