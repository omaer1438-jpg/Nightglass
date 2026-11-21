"""Filesystem locations. All case data lives under one local, git-ignored folder.

From source, the root is the project folder. In the packaged build it is the
folder that holds Nightglass.exe, next to tools\\, bin\\, envs\\ and cases\\.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: Set this to keep case data somewhere else (tests point it at a temp dir).
DATA_DIR_ENV = "NIGHTGLASS_DATA_DIR"


def data_dir() -> Path:
    override = os.environ.get(DATA_DIR_ENV)
    # Absolute, so tools started in their own folder (cwd: script) never resolve run paths against it.
    return Path(override).resolve() if override else PROJECT_ROOT / "cases"


def db_path() -> Path:
    return data_dir() / "nightglass.db"


def encrypted_db_path() -> Path:
    return data_dir() / "nightglass.db.enc"
