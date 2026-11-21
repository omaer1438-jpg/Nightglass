"""Evidence files: copied into the case folder, SHA-256 hashed, verifiable later."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core.db import Database
from core.runs import case_dir

MAX_EVIDENCE_BYTES = 500 * 1024 * 1024
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")


class EvidenceError(ValueError):
    """Shown to the user."""


@dataclass(frozen=True)
class EvidenceRecord:
    id: int
    case_id: int
    finding_id: int | None
    path: str
    sha256: str
    collected_at: datetime
    description: str

    @property
    def name(self) -> str:
        return Path(self.path).name

    @property
    def size(self) -> int:
        try:
            return Path(self.path).stat().st_size
        except OSError:
            return 0


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_file(path: Path | str, sha256: str) -> bool | None:
    """True if the file still matches the hash, False if changed or unreadable, None if missing.
    File work only, so it can run off the GUI thread."""
    path = Path(path)
    if not path.is_file():
        return None
    try:
        return sha256_of(path) == sha256
    except OSError:
        return False


def _store_copy(source: Path, folder: Path, digest: str) -> Path:
    """Copy into the evidence folder without ever touching a stored file: an existing copy with the
    same hash is reused; one that differs (it may have been tampered with) is left for verify() to flag."""
    safe = _SAFE_NAME.sub("_", source.name).strip() or "file"
    target, n = folder / f"{digest[:8]}_{safe}", 1
    while target.exists():
        if check_file(target, digest):
            return target
        n += 1
        target = folder / f"{digest[:8]}_{n}_{safe}"
    partial = target.with_name(target.name + ".part")
    try:
        shutil.copy2(source, partial)
        if sha256_of(partial) != digest:
            raise EvidenceError("The copy didn't match the original. Try again.")
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)
    return target


class EvidenceStore:
    def __init__(self, db: Database, root: Path | None = None):
        self.db = db
        self.root = root

    def add(self, case_id: int, source: Path | str, description: str = "",
            finding_id: int | None = None) -> EvidenceRecord:
        self.check_open(case_id)
        path, digest = self.copy_in(case_id, source)
        return self.record(case_id, path, digest, description, finding_id)

    def check_open(self, case_id: int) -> None:
        case = self.db.execute("SELECT status FROM cases WHERE id = ?", (case_id,)).fetchone()
        if case is None:
            raise EvidenceError("That case doesn't exist.")
        if case["status"] != "open":
            raise EvidenceError("The case is closed. Reopen it to add evidence.")

    def copy_in(self, case_id: int, source: Path | str) -> tuple[Path, str]:
        """Hash the file and copy it into the case's evidence folder. No database access, so the UI
        runs this on a worker thread and then calls record() on the GUI thread."""
        source = Path(source)
        try:
            if not source.is_file():
                raise EvidenceError("Choose a file that exists on this computer.")
            if source.stat().st_size > MAX_EVIDENCE_BYTES:
                raise EvidenceError(f"Evidence files can be at most {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB.")
            digest = sha256_of(source)
            folder = case_dir(case_id, self.root) / "evidence"
            folder.mkdir(parents=True, exist_ok=True)
            return _store_copy(source, folder, digest), digest
        except OSError as exc:
            raise EvidenceError(f"The file couldn't be read or copied ({exc.strerror or type(exc).__name__}).") from exc

    def record(self, case_id: int, path: Path, digest: str, description: str = "",
               finding_id: int | None = None) -> EvidenceRecord:
        self.check_open(case_id)
        if finding_id is not None and self.db.execute(
                "SELECT 1 FROM findings WHERE id = ? AND case_id = ?", (finding_id, case_id)).fetchone() is None:
            raise EvidenceError("That finding isn't part of this case.")
        cur = self.db.execute(
            "INSERT INTO evidence (case_id, finding_id, path, sha256, collected_at, description) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, finding_id, str(path), digest, datetime.now(timezone.utc).isoformat(timespec="seconds"),
             description.strip()[:500]),
        )
        self.db.execute("UPDATE cases SET updated_at = ? WHERE id = ?",
                        (datetime.now(timezone.utc).isoformat(timespec="seconds"), case_id))
        return self.get(cur.lastrowid)

    def get(self, evidence_id: int) -> EvidenceRecord:
        row = self.db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        return EvidenceRecord(row["id"], row["case_id"], row["finding_id"], row["path"], row["sha256"],
                              datetime.fromisoformat(row["collected_at"]), row["description"])

    def list(self, case_id: int) -> list[EvidenceRecord]:
        rows = self.db.execute("SELECT id FROM evidence WHERE case_id = ? ORDER BY collected_at, id", (case_id,))
        return [self.get(r["id"]) for r in rows]

    def verify(self, evidence_id: int) -> bool | None:
        """True if the stored file still matches its hash, False if changed, None if missing."""
        record = self.get(evidence_id)
        return check_file(record.path, record.sha256)
