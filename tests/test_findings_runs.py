"""Findings, run records, consent log, schema migration."""

from __future__ import annotations

import sqlite3

import pytest
from pydantic import ValidationError

from core.db import SCHEMA, Database, _split_statements
from core.findings import Finding, FindingStatus, FindingStore, ResultKind
from core.runs import ConsentLog, RunStore


@pytest.fixture
def case(manager, new_case):
    return manager.create_case(new_case())


def make(title="GitHub profile", **kw) -> Finding:
    data = dict(module="UserRecon", title=title, source="Sherlock", url="https://github.com/example_user")
    data.update(kw)
    return Finding(**data)


def test_new_findings_are_always_leads(db, case):
    store = FindingStore(db)
    [fid] = store.add(case.id, [make()])
    stored = store.get(fid)
    assert stored.status is FindingStatus.LEAD
    assert stored.display_status == "Lead"
    with pytest.raises(ValidationError):
        Finding(module="X", title="t", source="s", status="verified")  # adapters can't set status


def test_finding_urls_must_be_http(db):
    # Never stored as a clickable link; the text stays readable and the rest of the run is kept.
    for bad in ("javascript:alert(1)", "file:///C:/Windows", "https://example.com/a b", 42):
        finding = make(url=bad)
        assert finding.url is None and finding.value == str(bad)
    assert make(url="javascript:alert(1)", value="kept").value == "kept"


def test_oversized_fields_are_cut_not_fatal(db, case):
    long_url = "https://example.com/" + "a" * 3000
    finding = make(title="t" * 500, value="v" * 5000, notes="n" * 5000, raw_ref="r" * 600, url=long_url)
    assert len(finding.title) == 300 and finding.title.endswith("…")
    assert len(finding.value) == 4000 and finding.value.startswith("v")
    assert len(finding.notes) == 4000 and len(finding.raw_ref) == 500
    assert finding.url is None
    assert make(url=long_url).value == long_url  # the link stays readable as text
    [fid] = FindingStore(db).add(case.id, [finding])
    assert FindingStore(db).get(fid).title.endswith("…")


def test_list_filters_and_status_changes(db, case, manager):
    store = FindingStore(db)
    ids = store.add(case.id, [
        make(),
        make("Reddit profile", url="https://www.reddit.com/user/example_user"),
        make("Instagram", url=None, value="Blocked by bot detection", result=ResultKind.UNCERTAIN),
        make("MX record", module="DNSRecon", source="dnspython", url=None, value="mail.example.com",
             result=ResultKind.INFO),
    ])
    assert store.get(ids[2]).display_status == "Uncertain"
    verified = store.set_status(ids[0], "verified", "Bio links to example.com.")
    assert verified.status is FindingStatus.VERIFIED and verified.notes == "Bio links to example.com."
    store.set_status(ids[1], FindingStatus.REJECTED)

    assert [f.title for f in store.list(case.id, status="lead")] == ["Instagram", "MX record"]
    assert store.get(ids[3]).display_status == "Info"
    assert [f.title for f in store.list(case.id, module="DNSRecon")] == ["MX record"]
    assert [f.title for f in store.list(case.id, query="reddit")] == ["Reddit profile"]
    assert store.modules(case.id) == ["DNSRecon", "UserRecon"]
    counts = manager.counts(case.id)
    assert (counts.findings, counts.leads, counts.verified) == (4, 1, 1)  # info rows are not leads

    manager.close_case(case.id)
    with pytest.raises(ValueError, match="closed"):
        store.set_status(ids[2], "verified")


def test_run_records_and_folders(db, case, tmp_path):
    runs = RunStore(db, tmp_path)
    run = runs.create(case.id, "UserRecon", tool_id=None, external=True)
    assert run.status == "pending" and run.external_network
    assert run.work_dir.endswith(r"CASE-001\runs\r-0001") or run.work_dir.endswith("CASE-001/runs/r-0001")
    runs.mark_running(run.id)
    done = runs.finish(run.id, "succeeded", exit_code=0, output_bytes=2048, summary="9 found")
    assert done.status == "succeeded" and done.duration_s is not None and done.summary == "9 found"
    with pytest.raises(ValueError):
        runs.finish(run.id, "running")

    stuck = runs.create(case.id, "DNSRecon")
    runs.mark_running(stuck.id)
    assert runs.fail_interrupted() == 1
    assert runs.get(stuck.id).status == "failed"
    assert [r.id for r in runs.list(case.id)] == [stuck.id, run.id]


def test_consent_log(db, case):
    log = ConsentLog(db)
    assert log.next_ref() == "#C-0001"
    consent = log.record(case.id, "UserRecon", "Sherlock site list", "example_user", scope_confirmed=True)
    assert consent.ref == "#C-0001" and not consent.remembered
    with pytest.raises(ValueError):
        log.record(case.id, "PortScanner", "target host", "192.0.2.10", scope_confirmed=False, active=True)
    with pytest.raises(ValueError):
        log.record(case.id, "PortScanner", "target host", "192.0.2.10", scope_confirmed=True, active=True,
                   remembered=True)
    assert not log.remembered(case.id, "userrecon")
    log.remember(case.id, "userrecon")
    assert log.remembered(case.id, "userrecon")
    assert [c.module for c in log.list(case.id)] == ["UserRecon"]


def test_migrates_a_version_1_database(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    for statement in _split_statements(SCHEMA):
        conn.execute(statement)
    conn.execute("PRAGMA user_version = 1")
    conn.execute("INSERT INTO cases (name, purpose, authorized_scope, created_at, updated_at) "
                 "VALUES ('Old case', 'p', 's', 'x', 'x')")
    conn.commit()
    conn.close()

    with Database(path) as db:
        assert db.schema_version == 4
        assert "api_cache" in db.table_names()
        columns = {r["name"] for r in db.execute("PRAGMA table_info(findings)")}
        assert "result" in columns
        assert db.execute("SELECT name FROM cases").fetchone()["name"] == "Old case"


def test_verify_and_reject_show_in_the_activity_log(manager, new_case, db):
    from core.findings import Finding, FindingStore

    case = manager.create_case(new_case())
    store = FindingStore(db)
    first, second = store.add(case.id, [
        Finding(module="UserRecon", title="GitHub profile", value="example_user", source="Sherlock"),
        Finding(module="UserRecon", title="Old forum account", value="example_user", source="Sherlock"),
    ])
    store.set_status(first, "verified", note="My own account.")
    store.set_status(second, "rejected")
    events = {(a.event, a.detail) for a in manager.activity(case.id)}
    assert ("Finding verified", "GitHub profile") in events
    assert ("Finding rejected", "Old forum account") in events
