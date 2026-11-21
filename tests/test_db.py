import sqlite3

import pytest

from core.db import DEFAULT_SETTINGS, SCHEMA_VERSION, Database, SchemaError

EXPECTED_TABLES = {
    "cases", "targets", "tools", "runs", "findings", "evidence", "consents", "settings",
}


def test_creates_all_tables(db):
    assert EXPECTED_TABLES <= set(db.table_names())
    assert db.schema_version == SCHEMA_VERSION


def test_foreign_keys_enforced(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO targets (case_id, type, value, fingerprint, created_at) "
            "VALUES (999, 'username', 'example_user', ?, '2026-10-29T00:00:00+00:00')",
            ("0" * 64,),
        )


def _insert_case(db) -> int:
    return db.execute(
        "INSERT INTO cases (name, purpose, authorized_scope, created_at, updated_at) "
        "VALUES ('n', 'p', 's', '2026-10-29T00:00:00+00:00', '2026-10-29T00:00:00+00:00')"
    ).lastrowid


@pytest.mark.parametrize(
    "column, bad_value",
    [("status", "proof"), ("confidence", "certain")],
)
def test_finding_enums_are_checked(db, column, bad_value):
    case_id = _insert_case(db)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            f"INSERT INTO findings (case_id, module, title, source, collected_at, {column}) "
            "VALUES (?, 'UserRecon', 'GitHub profile', 'Sherlock', '2026-10-29T00:00:00+00:00', ?)",
            (case_id, bad_value),
        )


def test_findings_default_to_lead(db):
    case_id = _insert_case(db)
    db.execute(
        "INSERT INTO findings (case_id, module, title, source, collected_at) "
        "VALUES (?, 'UserRecon', 'GitHub profile', 'Sherlock', '2026-10-29T00:00:00+00:00')",
        (case_id,),
    )
    row = db.execute("SELECT status, confidence FROM findings").fetchone()
    assert (row["status"], row["confidence"]) == ("lead", "low")


def test_case_requires_purpose_and_scope(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO cases (name, purpose, authorized_scope, created_at, updated_at) "
            "VALUES ('n', '   ', 's', 'x', 'x')"
        )


def test_deleting_case_removes_its_data(db):
    case_id = _insert_case(db)
    db.execute(
        "INSERT INTO consents (case_id, module, provider, data_sent, consented_at, user_confirmed) "
        "VALUES (?, 'UserRecon', 'WhatsMyName sites', 'example_user', 'x', 1)",
        (case_id,),
    )
    db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    assert db.execute("SELECT COUNT(*) FROM consents").fetchone()[0] == 0


def test_default_settings_are_safe(db):
    assert db.get_setting("ask_before_external") is True
    for key in ("active.holehe", "active.phone_registration", "active.port_scan"):
        assert db.get_setting(key) is False


def test_settings_roundtrip_and_survive_reopen(db_path):
    with Database(db_path) as first:
        first.set_setting("default_timeout_s", 60)
        first.set_setting("last_case_id", 3)
    with Database(db_path) as second:
        assert second.get_setting("default_timeout_s") == 60
        assert second.get_setting("last_case_id") == 3
        assert second.get_setting("theme") == DEFAULT_SETTINGS["theme"]
        assert second.get_setting("missing", "fallback") == "fallback"


def test_refuses_newer_schema(db_path):
    with Database(db_path) as database:
        database.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(SchemaError):
        Database(db_path)


def test_transaction_rolls_back_on_error(db):
    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO cases (name, purpose, authorized_scope, created_at, updated_at) "
                "VALUES ('n', 'p', 's', 'x', 'x')"
            )
            raise RuntimeError("boom")
    assert db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0
