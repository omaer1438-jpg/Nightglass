"""Unified Finding schema (plan section 8.2) and storage.

Every adapter returns Findings. New findings are always stored as leads:
adapters cannot mark anything verified; only the user can (docs/PROJECT_RULES.md rule 6).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.db import Database


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, Enum):
    LEAD = "lead"
    VERIFIED = "verified"
    REJECTED = "rejected"


class ResultKind(str, Enum):
    FOUND = "found"          # something was found (a lead)
    UNCERTAIN = "uncertain"  # blocked, rate-limited or ambiguous
    INFO = "info"            # descriptive data (DNS record, metadata field, ...)


class Finding(BaseModel):
    """What an adapter returns. Status is not part of it: everything starts as a lead."""

    model_config = ConfigDict(extra="forbid")

    module: str = Field(min_length=1, max_length=60)
    title: str = Field(min_length=1, max_length=300)
    value: str | None = Field(None, max_length=4000)
    source: str = Field(min_length=1, max_length=120)
    url: str | None = Field(None, max_length=2048)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    confidence: Confidence = Confidence.LOW
    result: ResultKind = ResultKind.FOUND
    raw_ref: str | None = Field(None, max_length=500)
    notes: str = Field("", max_length=4000)

    @model_validator(mode="before")
    @classmethod
    def _fit(cls, data):
        """Tool and site output is untrusted: one oversized or odd field must not drop a whole run.
        Long text is cut with an ellipsis; a link that is not a plain http(s) URL is never stored as a link
        (it stays readable in value)."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        url = data.get("url")
        if url is not None and not _is_http_url(url):
            data["url"] = None
            if not data.get("value"):
                data["value"] = str(url)
        for key, limit in _TEXT_LIMITS.items():
            if isinstance(data.get(key), str) and len(data[key]) > limit:
                data[key] = data[key][:limit - 1] + "…"
        return data

    @field_validator("url")
    @classmethod
    def _http_url(cls, value: str | None) -> str | None:
        if value is not None and not _is_http_url(value):
            raise ValueError("finding URLs must be http(s) links")
        return value


_TEXT_LIMITS = {"title": 300, "value": 4000, "notes": 4000, "raw_ref": 500}


def _is_http_url(value) -> bool:
    return (isinstance(value, str) and len(value) <= 2048 and value.lower().startswith(("https://", "http://"))
            and not any(c.isspace() for c in value))


@dataclass(frozen=True)
class StoredFinding:
    id: int
    case_id: int
    run_id: int | None
    target_id: int | None
    module: str
    title: str
    value: str | None
    source: str
    url: str | None
    collected_at: datetime
    confidence: Confidence
    status: FindingStatus
    result: ResultKind
    raw_ref: str | None
    notes: str

    @property
    def display_status(self) -> str:
        if self.status is FindingStatus.LEAD and self.result is ResultKind.UNCERTAIN:
            return "Uncertain"
        if self.status is FindingStatus.LEAD and self.result is ResultKind.INFO:
            return "Info"  # descriptive data (file type, DNS record): not an identity lead
        return self.status.value.capitalize()


class FindingStore:
    def __init__(self, db: Database):
        self.db = db

    def add(self, case_id: int, findings: list[Finding], run_id: int | None = None,
            target_id: int | None = None) -> list[int]:
        ids = []
        with self.db.transaction() as conn:
            for f in findings:
                cur = conn.execute(
                    "INSERT INTO findings (case_id, run_id, target_id, module, title, value, source, url, "
                    "collected_at, confidence, status, result, raw_ref, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'lead', ?, ?, ?)",
                    (
                        case_id, run_id, target_id, f.module, f.title, f.value, f.source, f.url,
                        f.collected_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
                        f.confidence.value, f.result.value, f.raw_ref, f.notes,
                    ),
                )
                ids.append(cur.lastrowid)
        return ids

    def get(self, finding_id: int) -> StoredFinding:
        row = self.db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            raise KeyError(finding_id)
        return _from_row(row)

    def list(self, case_id: int, status: FindingStatus | str | None = None, module: str | None = None,
             query: str = "", run_id: int | None = None) -> list[StoredFinding]:
        sql = "SELECT * FROM findings WHERE case_id = ?"
        params: list = [case_id]
        if status:
            sql += " AND status = ?"
            params.append(FindingStatus(status).value)
        if module:
            sql += " AND module = ?"
            params.append(module)
        if run_id is not None:
            sql += " AND run_id = ?"
            params.append(run_id)
        for word in query.lower().split():
            sql += " AND lower(title || ' ' || COALESCE(value, '') || ' ' || source || ' ' || COALESCE(url, '')) LIKE ?"
            params.append(f"%{word}%")
        sql += " ORDER BY collected_at DESC, id"
        return [_from_row(r) for r in self.db.execute(sql, tuple(params))]

    def modules(self, case_id: int) -> list[str]:
        rows = self.db.execute("SELECT DISTINCT module FROM findings WHERE case_id = ? ORDER BY module", (case_id,))
        return [r["module"] for r in rows]

    def set_status(self, finding_id: int, status: FindingStatus | str, note: str | None = None) -> StoredFinding:
        status = FindingStatus(status)
        current = self.get(finding_id)
        case = self.db.execute("SELECT status FROM cases WHERE id = ?", (current.case_id,)).fetchone()
        if case["status"] != "open":
            raise ValueError("The case is closed. Reopen it to change findings.")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE findings SET status = ?, notes = COALESCE(?, notes), "
                "reviewed_at = CASE WHEN status = ? AND ? IS NULL THEN reviewed_at ELSE ? END WHERE id = ?",
                (status.value, note, status.value, note, now, finding_id),
            )
            conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, current.case_id))
        return self.get(finding_id)


def _from_row(row: sqlite3.Row) -> StoredFinding:
    return StoredFinding(
        id=row["id"],
        case_id=row["case_id"],
        run_id=row["run_id"],
        target_id=row["target_id"],
        module=row["module"],
        title=row["title"],
        value=row["value"],
        source=row["source"],
        url=row["url"],
        collected_at=datetime.fromisoformat(row["collected_at"]),
        confidence=Confidence(row["confidence"]),
        status=FindingStatus(row["status"]),
        result=ResultKind(row["result"]),
        raw_ref=row["raw_ref"],
        notes=row["notes"],
    )
