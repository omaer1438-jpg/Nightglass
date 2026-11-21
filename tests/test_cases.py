import pytest

from core.cases import (
    CaseError,
    CaseManager,
    CaseNotFound,
    LookupMode,
    NewCaseInvalid,
)
from core.db import Database
from core.validation import TargetType, ValidationError


def test_create_case_with_first_target(manager, new_case):
    case = manager.create_case(new_case())
    assert case.ref == "CASE-001"
    assert case.is_open and case.closed_at is None
    assert case.allowed_modes == (LookupMode.LOCAL, LookupMode.EXTERNAL_PASSIVE)
    assert case.retention_days == 90
    [target] = manager.list_targets(case.id)
    assert (target.type, target.value, target.input_source) == (
        TargetType.USERNAME, "example_user", "new_case",
    )


def test_target_is_optional(manager, new_case):
    case = manager.create_case(new_case(first_target_type=None, first_target_value=""))
    assert manager.list_targets(case.id) == []


def test_invalid_case_reports_every_field_and_saves_nothing(manager, new_case, db):
    with pytest.raises(NewCaseInvalid) as info:
        manager.create_case(
            new_case(
                name=" ",
                purpose="",
                authorized_scope="",
                allowed_modes=(),
                first_target_type="email",
                first_target_value="not-an-email",
            )
        )
    assert set(info.value.errors) == {
        "name", "purpose", "authorized_scope", "allowed_modes", "first_target",
    }
    assert db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0


def test_case_refs_are_never_reused(manager, new_case, db):
    first = manager.create_case(new_case())
    db.execute("DELETE FROM cases WHERE id = ?", (first.id,))
    assert manager.next_case_ref() == "CASE-002"
    assert manager.create_case(new_case()).ref == "CASE-002"


def test_save_close_reopen_keeps_all_data(manager, new_case, clock):
    case = manager.create_case(new_case())
    clock.advance(minutes=5)
    saved = manager.save_case(case.id, notes="Bio links to example.com.")
    assert saved.notes == "Bio links to example.com."
    assert saved.updated_at > case.updated_at

    clock.advance(minutes=5)
    closed = manager.close_case(case.id)
    assert closed.status == "closed" and closed.closed_at == clock.now

    with pytest.raises(CaseError):
        manager.save_case(case.id, notes="edit while closed")
    with pytest.raises(CaseError):
        manager.add_target(case.id, "domain", "example.com")
    with pytest.raises(CaseError):
        manager.close_case(case.id)

    reopened = manager.reopen_case(case.id)
    assert reopened.is_open and reopened.closed_at is None
    assert reopened.notes == "Bio links to example.com."
    assert reopened.purpose == case.purpose
    assert reopened.authorized_scope == case.authorized_scope
    assert [t.value for t in manager.list_targets(case.id)] == ["example_user"]
    with pytest.raises(CaseError):
        manager.reopen_case(case.id)


def test_case_survives_app_restart(db_path, clock, new_case):
    with Database(db_path) as first:
        case = CaseManager(first, now=clock).create_case(new_case())
        CaseManager(first, now=clock).save_case(case.id, notes="kept")
    with Database(db_path) as second:
        again = CaseManager(second, now=clock).get_case(case.id)
    assert (again.name, again.notes, again.allowed_modes) == (case.name, "kept", case.allowed_modes)


def test_add_target_validates_and_dedupes(manager, new_case):
    case = manager.create_case(new_case())
    target = manager.add_target(case.id, "domain", "Example.com")
    assert target.value == "example.com"
    with pytest.raises(CaseError):
        manager.add_target(case.id, "domain", "example.com.")
    with pytest.raises(ValidationError):
        manager.add_target(case.id, "ip", "192.0.2.999")
    assert manager.counts(case.id).targets == 2


def test_list_cases_puts_open_first(manager, new_case, clock):
    a = manager.create_case(new_case(name="A"))
    clock.advance(minutes=1)
    b = manager.create_case(new_case(name="B"))
    clock.advance(minutes=1)
    manager.close_case(b.id)
    assert [c.name for c in manager.list_cases()] == ["A", "B"]
    assert [c.name for c in manager.list_cases(status="closed")] == ["B"]
    assert manager.get_case(a.id).name == "A"


def test_get_missing_case(manager):
    with pytest.raises(CaseNotFound):
        manager.get_case(42)


def test_dashboard_stats(manager, new_case, db, clock):
    open_case = manager.create_case(new_case())
    other = manager.create_case(new_case(name="Own domain exposure audit"))
    manager.close_case(other.id)
    for status in ("lead", "lead", "verified", "rejected"):
        db.execute(
            "INSERT INTO findings (case_id, module, title, source, collected_at, status) "
            "VALUES (?, 'UserRecon', 'GitHub profile', 'Sherlock', ?, ?)",
            (open_case.id, clock.now.isoformat(), status),
        )
    db.execute(
        "INSERT INTO consents (case_id, module, provider, data_sent, consented_at, user_confirmed) "
        "VALUES (?, 'UserRecon', 'WhatsMyName sites', 'example_user', ?, 1)",
        (open_case.id, clock.now.isoformat()),
    )
    stats = manager.dashboard_stats()
    assert (stats.open_cases, stats.closed_this_week) == (1, 1)
    assert (stats.leads, stats.cases_with_leads, stats.verified) == (2, 1, 1)
    assert stats.external_lookups_7d == 1
    counts = manager.counts(open_case.id)
    assert (counts.findings, counts.leads, counts.verified) == (4, 2, 1)

    clock.advance(days=8)
    later = manager.dashboard_stats()
    assert (later.closed_this_week, later.external_lookups_7d) == (0, 0)


def test_activity_is_newest_first(manager, new_case, clock):
    case = manager.create_case(new_case())
    clock.advance(minutes=3)
    manager.add_target(case.id, "domain", "example.com")
    clock.advance(minutes=3)
    manager.close_case(case.id)
    events = [a.event for a in manager.activity(case.id)]
    assert events == ["Case closed", "Target added", "Target added", "Case opened"]
