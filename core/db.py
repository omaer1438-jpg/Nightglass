"""SQLite storage for cases and everything collected under them (plan section 10).

One local database file. Timestamps are ISO 8601 UTC strings. Child rows of a
case are deleted with the case (PDPL: delete what the case no longer needs).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from core.dbcrypto import DbCrypto, plain_files, wipe_file

SCHEMA_VERSION = 4

SCHEMA = """
CREATE TABLE cases (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL CHECK (length(trim(name)) > 0),
    purpose          TEXT    NOT NULL CHECK (length(trim(purpose)) > 0),
    authorized_scope TEXT    NOT NULL CHECK (length(trim(authorized_scope)) > 0),
    allowed_modes    TEXT    NOT NULL DEFAULT '["local"]',      -- JSON list of LookupMode values
    notes            TEXT    NOT NULL DEFAULT '',
    status           TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    retention_days   INTEGER CHECK (retention_days IS NULL OR retention_days > 0),  -- NULL = keep
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    closed_at        TEXT
);

CREATE TABLE targets (
    id           INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    type         TEXT    NOT NULL CHECK (type IN
                     ('username', 'email', 'phone', 'ip', 'domain', 'url', 'file', 'other')),
    value        TEXT    NOT NULL,
    fingerprint  TEXT    NOT NULL CHECK (length(fingerprint) = 64),
    input_source TEXT    NOT NULL DEFAULT 'manual',
    created_at   TEXT    NOT NULL,
    UNIQUE (case_id, fingerprint)
);

CREATE TABLE tools (
    id               TEXT    PRIMARY KEY,
    name             TEXT    NOT NULL,
    category         TEXT    NOT NULL,
    official_url     TEXT    NOT NULL,
    license          TEXT,
    open_source      INTEGER NOT NULL DEFAULT 0 CHECK (open_source IN (0, 1)),
    labels           TEXT    NOT NULL DEFAULT '[]',               -- JSON: local/external/passive/active/api_key
    api_requirements TEXT,
    launch_method    TEXT    NOT NULL,                            -- subprocess / python / web_api / browser
    review_date      TEXT
);

CREATE TABLE runs (
    id               INTEGER PRIMARY KEY,
    case_id          INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    target_id        INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    tool_id          TEXT    REFERENCES tools(id) ON DELETE SET NULL,
    module           TEXT,
    started_at       TEXT    NOT NULL,
    ended_at         TEXT,
    status           TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN
                         ('pending', 'running', 'succeeded', 'failed', 'timed_out', 'cancelled')),
    exit_code        INTEGER,
    log_path         TEXT,
    work_dir         TEXT,
    external_network INTEGER NOT NULL DEFAULT 0 CHECK (external_network IN (0, 1)),
    active           INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1))
);

CREATE TABLE findings (
    id           INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id       INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    target_id    INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    module       TEXT    NOT NULL,
    title        TEXT    NOT NULL,
    value        TEXT,
    source       TEXT    NOT NULL,
    url          TEXT,
    collected_at TEXT    NOT NULL,
    confidence   TEXT    NOT NULL DEFAULT 'low' CHECK (confidence IN ('low', 'medium', 'high')),
    status       TEXT    NOT NULL DEFAULT 'lead' CHECK (status IN ('lead', 'verified', 'rejected')),
    raw_ref      TEXT,
    notes        TEXT    NOT NULL DEFAULT ''                      -- verification notes
);

CREATE TABLE evidence (
    id           INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    finding_id   INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    path         TEXT    NOT NULL,
    sha256       TEXT    NOT NULL CHECK (length(sha256) = 64),
    collected_at TEXT    NOT NULL,
    description  TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE consents (
    id              INTEGER PRIMARY KEY,
    case_id         INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id          INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    module          TEXT    NOT NULL,
    provider        TEXT    NOT NULL,
    data_sent       TEXT    NOT NULL,
    consented_at    TEXT    NOT NULL,
    user_confirmed  INTEGER NOT NULL CHECK (user_confirmed IN (0, 1)),
    scope_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (scope_confirmed IN (0, 1)),
    active          INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1))
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL                                           -- JSON
);

CREATE INDEX idx_targets_case  ON targets(case_id);
CREATE INDEX idx_runs_case     ON runs(case_id);
CREATE INDEX idx_findings_case ON findings(case_id, status);
CREATE INDEX idx_evidence_case ON evidence(case_id);
CREATE INDEX idx_consents_case ON consents(case_id, consented_at);
"""

#: Applied in order to bring an older database up to SCHEMA_VERSION.
MIGRATIONS: dict[int, str] = {
    2: """
    ALTER TABLE runs ADD COLUMN output_bytes INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE runs ADD COLUMN summary TEXT NOT NULL DEFAULT '';
    ALTER TABLE runs ADD COLUMN error TEXT;
    ALTER TABLE findings ADD COLUMN result TEXT NOT NULL DEFAULT 'found'
        CHECK (result IN ('found', 'uncertain', 'info'));
    ALTER TABLE consents ADD COLUMN remembered INTEGER NOT NULL DEFAULT 0 CHECK (remembered IN (0, 1));
    CREATE TABLE api_cache (
        provider   TEXT NOT NULL,
        key        TEXT NOT NULL,                                 -- sha256 of the request
        response   TEXT NOT NULL,
        fetched_at TEXT NOT NULL,
        PRIMARY KEY (provider, key)
    );
    CREATE INDEX idx_runs_case_started ON runs(case_id, started_at);
    """,
    # Case map board: saved card positions ('pos'), sticky notes ('note', key n:<id>) and
    # analyst strings ('link', key l:<id>). Deleted with the case.
    3: """
    CREATE TABLE board_items (
        id         INTEGER PRIMARY KEY,
        case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        kind       TEXT    NOT NULL CHECK (kind IN ('pos', 'note', 'link')),
        key        TEXT    NOT NULL,
        x          REAL,
        y          REAL,
        pinned     INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
        text       TEXT    NOT NULL DEFAULT '',
        a_key      TEXT,
        b_key      TEXT,
        created_at TEXT    NOT NULL
    );
    CREATE UNIQUE INDEX idx_board_case_key ON board_items(case_id, kind, key);
    """,
    4: """
    ALTER TABLE findings ADD COLUMN reviewed_at TEXT;               -- last verify / keep / reject (Activity log)
    """,
}

#: Inserted once; user changes are never overwritten. Active modules start off (rule 5).
DEFAULT_SETTINGS: dict[str, Any] = {
    "theme": "dark",
    "language": "en",
    "results_view": "console",
    "timeout_cap_s": 0,                  # 0 = each tool's own limit (key renamed: the old 180 s seed never applied)
    "max_output_kb": 2048,
    "ask_before_external": True,
    "cache_external_results": True,
    "encrypt_database": False,
    "retention_days": 90,
    "active.holehe": False,
    "active.phone_registration": False,
    "active.port_scan": False,
    "last_case_id": None,
}


class SchemaError(RuntimeError):
    """The database was written by a newer version of Nightglass."""


class Database:
    def __init__(self, path: Path | str, crypto: DbCrypto | None = None, data: bytes | None = None):
        """Plain file database, or (with `crypto`) an in-memory database persisted encrypted.

        `data` is the decrypted database from DbCrypto.unlock(); omit it for a new encrypted file.
        """
        self.path = Path(path)
        self._crypto = crypto
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # Autocommit mode: writes are grouped explicitly with transaction().
        self._conn = sqlite3.connect(":memory:" if crypto else str(path), isolation_level=None)
        if crypto and data:
            self._conn.deserialize(_without_wal(data))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if str(path) != ":memory:" and not crypto:
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()
        self._persist()

    @property
    def encrypted(self) -> bool:
        return self._crypto is not None

    @property
    def cache_path(self) -> Path | None:
        """A real SQLite file other threads may open (None when encrypted: no plaintext on disk)."""
        return None if self._crypto or str(self.path) == ":memory:" else self.path

    def _persist(self) -> None:
        if self._crypto is not None and not self._conn.in_transaction:
            self._crypto.save(self._conn.serialize())

    def serialize(self) -> bytes:
        return self._conn.serialize()

    def change_password(self, new_password: str) -> None:
        if self._crypto is None:
            raise ValueError("The database is not encrypted.")
        self._crypto.rekey(new_password)
        self._persist()

    # -- connection ---------------------------------------------------------

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        if getattr(self, "_closed", False):
            return
        self._persist()
        self._conn.close()
        self._closed = True

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")
        self._persist()

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        cursor = self._conn.execute(sql, params)
        if self._crypto is not None and not sql.lstrip()[:6].upper().startswith(("SELECT", "PRAGMA")):
            self._persist()
        return cursor

    @property
    def schema_version(self) -> int:
        return self._conn.execute("PRAGMA user_version").fetchone()[0]

    def _migrate(self) -> None:
        version = self.schema_version
        if version > SCHEMA_VERSION:
            raise SchemaError(
                f"{self.path} uses schema v{version}; this build supports up to v{SCHEMA_VERSION}."
            )
        # Statement by statement: executescript() would commit mid-transaction.
        if version == 0:
            with self.transaction() as conn:
                for statement in _split_statements(SCHEMA):
                    conn.execute(statement)
                conn.execute("PRAGMA user_version = 1")
            version = 1
        for target in range(version + 1, SCHEMA_VERSION + 1):
            with self.transaction() as conn:
                for statement in _split_statements(MIGRATIONS[target]):
                    conn.execute(statement)
                conn.execute(f"PRAGMA user_version = {target}")
        with self.transaction() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                [(key, json.dumps(value)) for key, value in DEFAULT_SETTINGS.items()],
            )

    # -- settings -----------------------------------------------------------

    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return default if row is None else json.loads(row["value"])

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )

    def table_names(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        )
        return [row["name"] for row in rows]


def _split_statements(script: str) -> list[str]:
    """Split the schema on ';' (it contains no string literals with semicolons)."""
    lines = [line.split("--", 1)[0] for line in script.splitlines()]
    return [stmt.strip() for stmt in "\n".join(lines).split(";") if stmt.strip()]


# ---------------------------------------------------------------- encryption on/off


def _without_wal(data: bytes) -> bytes:
    """Header bytes 18-19 = 2 mark a WAL database; an in-memory copy must use rollback mode (1)."""
    if len(data) >= 20 and data[18:20] == b"\x02\x02":
        return data[:18] + b"\x01\x01" + data[20:]
    return data


def encrypt_existing(plain_path: Path, enc_path: Path, password: str, data: bytes | None = None) -> None:
    """Write an encrypted copy of a plain database, then wipe the plain file and its WAL/SHM."""
    if data is None:
        source = sqlite3.connect(str(plain_path))
        source.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # fold the WAL into the main file first
        data = source.serialize()
        source.close()
    crypto = DbCrypto.create(enc_path, password)
    crypto.save(_without_wal(data))
    for path in plain_files(plain_path):
        wipe_file(path)


def decrypt_existing(enc_path: Path, plain_path: Path, data: bytes) -> None:
    """Turn encryption off: write the database as a normal SQLite file and remove the encrypted one."""
    memory = sqlite3.connect(":memory:")
    memory.deserialize(data)
    target = sqlite3.connect(str(plain_path))
    memory.backup(target)  # copies every page into the file
    target.close()
    memory.close()
    Path(enc_path).unlink(missing_ok=True)
