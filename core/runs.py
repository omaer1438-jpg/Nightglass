"""Run records, per-run work folders and the consent log."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core import paths
from core.cases import case_ref
from core.db import Database

RUN_STATUSES = ("pending", "running", "succeeded", "failed", "timed_out", "cancelled")

MIN_NEEDLE = 3  # shorter values ("6") would match unrelated lines
MAX_EVIDENCE_LINE = 400


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def case_dir(case_id: int, root: Path | None = None) -> Path:
    """cases/CASE-001/ - everything collected for one case lives under here."""
    return (root or paths.data_dir()) / case_ref(case_id)


@dataclass(frozen=True)
class RunRecord:
    id: int
    case_id: int
    target_id: int | None
    tool_id: str | None
    module: str | None
    started_at: datetime
    ended_at: datetime | None
    status: str
    exit_code: int | None
    log_path: str | None
    work_dir: str | None
    external_network: bool
    active: bool
    output_bytes: int
    summary: str
    error: str | None

    @property
    def duration_s(self) -> float | None:
        return (self.ended_at - self.started_at).total_seconds() if self.ended_at else None


class RunStore:
    def __init__(self, db: Database, root: Path | None = None):
        self.db = db
        self.root = root

    def create(self, case_id: int, module: str, *, target_id: int | None = None, tool_id: str | None = None,
               external: bool = False, active: bool = False) -> RunRecord:
        with self.db.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO runs (case_id, target_id, tool_id, module, started_at, status, external_network, active) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
                (case_id, target_id, tool_id, module, _now(), int(external), int(active)),
            )
            run_id = cur.lastrowid
            work_dir = case_dir(case_id, self.root) / "runs" / f"r-{run_id:04d}"
            work_dir.mkdir(parents=True, exist_ok=True)
            conn.execute(
                "UPDATE runs SET work_dir = ?, log_path = ? WHERE id = ?",
                (str(work_dir), str(work_dir / "run.log"), run_id),
            )
        return self.get(run_id)

    def mark_running(self, run_id: int) -> None:
        self.db.execute("UPDATE runs SET status = 'running', started_at = ? WHERE id = ?", (_now(), run_id))

    def finish(self, run_id: int, status: str, *, exit_code: int | None = None, output_bytes: int = 0,
               summary: str = "", error: str | None = None) -> RunRecord:
        if status not in RUN_STATUSES[2:]:
            raise ValueError(f"not a final run status: {status}")
        self.db.execute(
            "UPDATE runs SET status = ?, ended_at = ?, exit_code = ?, output_bytes = ?, summary = ?, error = ? "
            "WHERE id = ?",
            (status, _now(), exit_code, output_bytes, summary, error, run_id),
        )
        return self.get(run_id)

    def get(self, run_id: int) -> RunRecord:
        row = self.db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        return _run_from_row(row)

    def list(self, case_id: int) -> list[RunRecord]:
        rows = self.db.execute("SELECT * FROM runs WHERE case_id = ? ORDER BY id DESC", (case_id,))
        return [_run_from_row(r) for r in rows]

    def fail_interrupted(self) -> int:
        """Runs left 'running' by a crash or forced exit are marked failed at startup."""
        cur = self.db.execute(
            "UPDATE runs SET status = 'failed', ended_at = ?, error = 'Interrupted (app closed during the run)' "
            "WHERE status IN ('pending', 'running')",
            (_now(),),
        )
        return cur.rowcount


def _run_from_row(row: sqlite3.Row) -> RunRecord:
    parse = lambda v: datetime.fromisoformat(v) if v else None  # noqa: E731
    return RunRecord(
        id=row["id"], case_id=row["case_id"], target_id=row["target_id"], tool_id=row["tool_id"],
        module=row["module"], started_at=parse(row["started_at"]), ended_at=parse(row["ended_at"]),
        status=row["status"], exit_code=row["exit_code"], log_path=row["log_path"], work_dir=row["work_dir"],
        external_network=bool(row["external_network"]), active=bool(row["active"]),
        output_bytes=row["output_bytes"], summary=row["summary"], error=row["error"],
    )


# ---------------------------------------------------------------- consent


@dataclass(frozen=True)
class ConsentRecord:
    id: int
    case_id: int
    run_id: int | None
    module: str
    provider: str
    data_sent: str
    consented_at: datetime
    scope_confirmed: bool
    active: bool
    remembered: bool

    @property
    def ref(self) -> str:
        return f"#C-{self.id:04d}"


def evidence_lines(log_path: Path, finding, limit: int = 8) -> list[str]:
    """What the tool actually printed about this finding: the raw lines its result rests on."""
    needles = [n for n in (finding.url, finding.value) if n and len(n) >= MIN_NEEDLE]
    if not needles or not log_path.is_file():
        return []
    found = []
    with log_path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.startswith("#") and any(needle in line for needle in needles):
                found.append(line.strip()[:MAX_EVIDENCE_LINE])
                if len(found) == limit:
                    break
    return found


class ConsentLog:
    """Every external or active lookup is logged here (docs/PROJECT_RULES.md rule 4)."""

    def __init__(self, db: Database):
        self.db = db

    def record(self, case_id: int, module: str, provider: str, data_sent: str, *, run_id: int | None = None,
               scope_confirmed: bool, active: bool = False, remembered: bool = False) -> ConsentRecord:
        if active and (remembered or not scope_confirmed):
            raise ValueError("active lookups need a fresh, scope-confirmed consent every time")
        cur = self.db.execute(
            "INSERT INTO consents (case_id, run_id, module, provider, data_sent, consented_at, user_confirmed, "
            "scope_confirmed, active, remembered) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
            (case_id, run_id, module, provider, data_sent, _now(), int(scope_confirmed), int(active), int(remembered)),
        )
        return self.get(cur.lastrowid)

    def attach_run(self, consent_id: int, run_id: int) -> None:
        self.db.execute("UPDATE consents SET run_id = ? WHERE id = ?", (run_id, consent_id))

    def get(self, consent_id: int) -> ConsentRecord:
        row = self.db.execute("SELECT * FROM consents WHERE id = ?", (consent_id,)).fetchone()
        return ConsentRecord(
            id=row["id"], case_id=row["case_id"], run_id=row["run_id"], module=row["module"],
            provider=row["provider"], data_sent=row["data_sent"],
            consented_at=datetime.fromisoformat(row["consented_at"]),
            scope_confirmed=bool(row["scope_confirmed"]), active=bool(row["active"]),
            remembered=bool(row["remembered"]),
        )

    def next_ref(self) -> str:
        row = self.db.execute("SELECT COALESCE(MAX(id), 0) + 1 AS n FROM consents").fetchone()
        return f"#C-{row['n']:04d}"

    def list(self, case_id: int) -> list[ConsentRecord]:
        rows = self.db.execute("SELECT id FROM consents WHERE case_id = ? ORDER BY id DESC", (case_id,))
        return [self.get(r["id"]) for r in rows]

    # "Don't ask again for this module in this case" (never for active modules).
    def remembered(self, case_id: int, module: str) -> bool:
        return bool(self.db.get_setting(f"consent.remember.{case_id}.{module}", False))

    def remember(self, case_id: int, module: str) -> None:
        self.db.set_setting(f"consent.remember.{case_id}.{module}", True)
