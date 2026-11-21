"""Case manager: create, save, close, reopen and list cases and their targets.

Every case starts with a purpose and an authorized scope (plan section 7).
Closed cases are read-only until reopened.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from core.db import Database
from core.validation import TargetType, ValidationError, fingerprint, validate_target

MAX_NAME_LENGTH = 120
MAX_TEXT_LENGTH = 4000


class LookupMode(str, Enum):
    LOCAL = "local"
    EXTERNAL_PASSIVE = "external_passive"
    ACTIVE = "active"


class CaseError(ValueError):
    """A case operation was refused. The message is shown to the user."""


class CaseNotFound(KeyError):
    pass


@dataclass(frozen=True)
class Case:
    id: int
    name: str
    purpose: str
    authorized_scope: str
    allowed_modes: tuple[LookupMode, ...]
    notes: str
    status: str
    retention_days: int | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None

    @property
    def ref(self) -> str:
        return case_ref(self.id)

    @property
    def is_open(self) -> bool:
        return self.status == "open"


@dataclass(frozen=True)
class Target:
    id: int
    case_id: int
    type: TargetType
    value: str
    fingerprint: str
    input_source: str
    created_at: datetime


@dataclass(frozen=True)
class CaseCounts:
    targets: int = 0
    findings: int = 0
    leads: int = 0
    verified: int = 0
    evidence: int = 0


@dataclass(frozen=True)
class DashboardStats:
    open_cases: int
    closed_this_week: int
    leads: int
    cases_with_leads: int
    verified: int
    external_lookups_7d: int


@dataclass(frozen=True)
class Activity:
    at: datetime
    event: str
    detail: str


@dataclass
class NewCase:
    name: str
    purpose: str
    authorized_scope: str
    allowed_modes: Sequence[LookupMode | str] = (LookupMode.LOCAL,)
    first_target_type: TargetType | str | None = None
    first_target_value: str = ""


class NewCaseInvalid(CaseError):
    """Raised by create_case. `errors` maps field name -> message."""

    def __init__(self, errors: dict[str, str]):
        super().__init__("; ".join(errors.values()))
        self.errors = errors


def case_ref(case_id: int) -> str:
    return f"CASE-{case_id:03d}"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class CaseManager:
    def __init__(self, db: Database, now: Callable[[], datetime] = _now_utc):
        self.db = db
        self._now = now

    # -- create -------------------------------------------------------------

    def validate_new_case(self, new: NewCase) -> tuple[dict[str, str], str | None]:
        """Return (errors by field, normalized first target or None)."""
        errors: dict[str, str] = {}
        name = new.name.strip()
        if not name:
            errors["name"] = "Give the case a name."
        elif len(name) > MAX_NAME_LENGTH:
            errors["name"] = f"Keep the name under {MAX_NAME_LENGTH} characters."
        if not new.purpose.strip():
            errors["purpose"] = "Describe why this case exists."
        elif len(new.purpose) > MAX_TEXT_LENGTH:
            errors["purpose"] = f"Keep the purpose under {MAX_TEXT_LENGTH} characters."
        if not new.authorized_scope.strip():
            errors["authorized_scope"] = (
                "Record what you are authorized to look at. Active modules check this scope."
            )
        elif len(new.authorized_scope) > MAX_TEXT_LENGTH:
            errors["authorized_scope"] = f"Keep the scope under {MAX_TEXT_LENGTH} characters."
        try:
            modes = [LookupMode(m) for m in new.allowed_modes]
        except ValueError:
            modes = []
        if not modes:
            errors["allowed_modes"] = "Allow at least one lookup mode."

        normalized = None
        if new.first_target_value.strip():
            if new.first_target_type is None:
                errors["first_target"] = "Pick the target type."
            else:
                try:
                    normalized = validate_target(new.first_target_type, new.first_target_value)
                except ValidationError as exc:
                    errors["first_target"] = str(exc)
        return errors, normalized

    def create_case(self, new: NewCase) -> Case:
        errors, normalized_target = self.validate_new_case(new)
        if errors:
            raise NewCaseInvalid(errors)
        modes = sorted({LookupMode(m) for m in new.allowed_modes}, key=list(LookupMode).index)
        now = _iso(self._now())
        retention = self.db.get_setting("retention_days", 90)
        with self.db.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO cases (name, purpose, authorized_scope, allowed_modes, "
                "retention_days, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    new.name.strip(),
                    new.purpose.strip(),
                    new.authorized_scope.strip(),
                    json.dumps([m.value for m in modes]),
                    retention,
                    now,
                    now,
                ),
            )
            case_id = cur.lastrowid
            if normalized_target is not None:
                kind = TargetType(new.first_target_type)
                self._insert_target(conn, case_id, kind, normalized_target, "new_case", now)
        return self.get_case(case_id)

    def next_case_ref(self) -> str:
        row = self.db.execute("SELECT seq FROM sqlite_sequence WHERE name = 'cases'").fetchone()
        return case_ref((row["seq"] if row else 0) + 1)

    # -- read ---------------------------------------------------------------

    def get_case(self, case_id: int) -> Case:
        row = self.db.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseNotFound(case_id)
        return _case_from_row(row)

    def list_cases(self, status: str | None = None, limit: int | None = None) -> list[Case]:
        sql = "SELECT * FROM cases"
        params: list = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        # Open cases first, then most recently touched.
        sql += " ORDER BY status = 'closed', updated_at DESC, id DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return [_case_from_row(r) for r in self.db.execute(sql, tuple(params))]

    def list_targets(self, case_id: int) -> list[Target]:
        rows = self.db.execute(
            "SELECT * FROM targets WHERE case_id = ? ORDER BY created_at, id", (case_id,)
        )
        return [_target_from_row(r) for r in rows]

    def counts(self, case_id: int) -> CaseCounts:
        row = self.db.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM targets  WHERE case_id = :id) AS targets,
              (SELECT COUNT(*) FROM findings WHERE case_id = :id) AS findings,
              (SELECT COUNT(*) FROM findings WHERE case_id = :id AND status = 'lead' AND result != 'info') AS leads,
              (SELECT COUNT(*) FROM findings WHERE case_id = :id AND status = 'verified') AS verified,
              (SELECT COUNT(*) FROM evidence WHERE case_id = :id) AS evidence
            """,
            {"id": case_id},
        ).fetchone()
        return CaseCounts(**dict(row))

    def dashboard_stats(self) -> DashboardStats:
        week_ago = _iso(self._now() - timedelta(days=7))
        row = self.db.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM cases WHERE status = 'open') AS open_cases,
              (SELECT COUNT(*) FROM cases WHERE status = 'closed' AND closed_at >= :since)
                  AS closed_this_week,
              (SELECT COUNT(*) FROM findings WHERE status = 'lead' AND result != 'info') AS leads,
              (SELECT COUNT(DISTINCT case_id) FROM findings WHERE status = 'lead' AND result != 'info')
                  AS cases_with_leads,
              (SELECT COUNT(*) FROM findings WHERE status = 'verified') AS verified,
              (SELECT COUNT(*) FROM consents WHERE consented_at >= :since) AS external_lookups_7d
            """,
            {"since": week_ago},
        ).fetchone()
        return DashboardStats(**dict(row))

    def activity(self, case_id: int, limit: int = 50) -> list[Activity]:
        rows = self.db.execute(
            """
            SELECT created_at AS at, 0 AS seq, 'Case opened' AS event, 'scope recorded' AS detail
              FROM cases WHERE id = :id
            UNION ALL
            SELECT closed_at, 9, 'Case closed', '' FROM cases WHERE id = :id AND closed_at IS NOT NULL
            UNION ALL
            SELECT created_at, 1, 'Target added', type || ' · ' || value
              FROM targets WHERE case_id = :id
            UNION ALL
            SELECT consented_at, 2, 'Consent logged', data_sent || ' → ' || provider
              FROM consents WHERE case_id = :id
            UNION ALL
            SELECT ended_at, 3, 'Run finished', COALESCE(module, tool_id, '')
              FROM runs WHERE case_id = :id AND ended_at IS NOT NULL
            UNION ALL
            SELECT collected_at, 4, 'Evidence added', path FROM evidence WHERE case_id = :id
            UNION ALL
            SELECT reviewed_at, 5, CASE status WHEN 'verified' THEN 'Finding verified'
                                               WHEN 'rejected' THEN 'Finding rejected'
                                               ELSE 'Finding kept as lead' END, title
              FROM findings WHERE case_id = :id AND reviewed_at IS NOT NULL
            ORDER BY at DESC, seq DESC
            LIMIT :limit
            """,
            {"id": case_id, "limit": limit},
        )
        return [Activity(_parse(r["at"]), r["event"], r["detail"]) for r in rows]

    # -- update -------------------------------------------------------------

    def save_case(
        self,
        case_id: int,
        *,
        name: str | None = None,
        purpose: str | None = None,
        authorized_scope: str | None = None,
        notes: str | None = None,
    ) -> Case:
        case = self._require_open(case_id)
        updates: dict[str, str] = {}
        for key, value in (("name", name), ("purpose", purpose), ("authorized_scope", authorized_scope)):
            if value is not None:
                if not value.strip():
                    raise CaseError(f"The {key.replace('_', ' ')} can't be empty.")
                updates[key] = value.strip()
        if notes is not None:
            if len(notes) > 200_000:
                raise CaseError("Notes are too long to save.")
            updates["notes"] = notes
        if not updates:
            return case
        updates["updated_at"] = _iso(self._now())
        assignments = ", ".join(f"{column} = :{column}" for column in updates)
        with self.db.transaction() as conn:
            conn.execute(f"UPDATE cases SET {assignments} WHERE id = :id", {**updates, "id": case_id})
        return self.get_case(case_id)

    def close_case(self, case_id: int) -> Case:
        self._require_open(case_id)
        now = _iso(self._now())
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE cases SET status = 'closed', closed_at = ?, updated_at = ? WHERE id = ?",
                (now, now, case_id),
            )
        return self.get_case(case_id)

    def reopen_case(self, case_id: int) -> Case:
        case = self.get_case(case_id)
        if case.is_open:
            raise CaseError(f"{case.ref} is already open.")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE cases SET status = 'open', closed_at = NULL, updated_at = ? WHERE id = ?",
                (_iso(self._now()), case_id),
            )
        return self.get_case(case_id)

    def add_target(
        self, case_id: int, target_type: TargetType | str, raw_value: str, input_source: str = "manual"
    ) -> Target:
        self._require_open(case_id)
        kind = TargetType(target_type)
        normalized = validate_target(kind, raw_value)
        now = _iso(self._now())
        try:
            with self.db.transaction() as conn:
                target_id = self._insert_target(conn, case_id, kind, normalized, input_source, now)
                conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc):
                raise CaseError("This target is already in the case.") from exc
            raise
        row = self.db.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return _target_from_row(row)

    # -- helpers ------------------------------------------------------------

    def _require_open(self, case_id: int) -> Case:
        case = self.get_case(case_id)
        if not case.is_open:
            raise CaseError(f"{case.ref} is closed. Reopen it to make changes.")
        return case

    @staticmethod
    def _insert_target(
        conn: sqlite3.Connection, case_id: int, kind: TargetType, value: str, source: str, now: str
    ) -> int:
        cur = conn.execute(
            "INSERT INTO targets (case_id, type, value, fingerprint, input_source, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, kind.value, value, fingerprint(kind, value), source, now),
        )
        return cur.lastrowid


def _case_from_row(row: sqlite3.Row) -> Case:
    return Case(
        id=row["id"],
        name=row["name"],
        purpose=row["purpose"],
        authorized_scope=row["authorized_scope"],
        allowed_modes=tuple(LookupMode(m) for m in json.loads(row["allowed_modes"])),
        notes=row["notes"],
        status=row["status"],
        retention_days=row["retention_days"],
        created_at=_parse(row["created_at"]),
        updated_at=_parse(row["updated_at"]),
        closed_at=_parse(row["closed_at"]),
    )


def _target_from_row(row: sqlite3.Row) -> Target:
    return Target(
        id=row["id"],
        case_id=row["case_id"],
        type=TargetType(row["type"]),
        value=row["value"],
        fingerprint=row["fingerprint"],
        input_source=row["input_source"],
        created_at=_parse(row["created_at"]),
    )
