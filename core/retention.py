"""Deleting case data: manual deletion and retention for closed cases (PDPL: keep only what's needed)."""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.cases import CaseManager
from core.db import Database
from core.net import CACHE_TTL
from core.runs import case_dir


def delete_case(db: Database, case_id: int, root: Path | None = None) -> str:
    """Remove the case, everything stored under it, and its folder. Returns the case ref."""
    case = CaseManager(db).get_case(case_id)
    with db.transaction() as conn:
        conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))  # targets/runs/findings/... cascade
        conn.execute("DELETE FROM settings WHERE key LIKE ?", (f"consent.remember.{case_id}.%",))
        # Cached provider answers hold target data but aren't keyed by case: a deleted case clears them all.
        conn.execute("DELETE FROM api_cache")
    if db.get_setting("last_case_id") == case_id:
        db.set_setting("last_case_id", None)
    folder = case_dir(case_id, root)
    if folder.exists():
        shutil.rmtree(folder, ignore_errors=True)
    return case.ref


def purge_expired(db: Database, now: datetime | None = None, root: Path | None = None) -> list[str]:
    """Delete closed cases whose retention period has passed, and stale cached provider answers."""
    now = now or datetime.now(timezone.utc)
    removed = []
    rows = db.execute(
        "SELECT id, closed_at, retention_days FROM cases WHERE status = 'closed' AND retention_days IS NOT NULL"
    ).fetchall()
    for row in rows:
        closed = datetime.fromisoformat(row["closed_at"])
        if closed + timedelta(days=row["retention_days"]) <= now:
            removed.append(delete_case(db, row["id"], root))
    db.execute("DELETE FROM api_cache WHERE fetched_at < ?", ((now - CACHE_TTL).isoformat(timespec="seconds"),))
    return removed
