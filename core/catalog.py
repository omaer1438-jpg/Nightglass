"""Tool catalog: load tools/*.yaml, report bad manifests, filter, and sync to the DB.

The catalog is plain files, so it can be reviewed and updated without
rebuilding the app (plan section 8.3). A broken manifest never stops the app;
it is skipped and reported.
"""

from __future__ import annotations

import importlib.util
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from core.db import Database
from core.manifest import Category, Label, LaunchKind, ToolManifest
from core.paths import PROJECT_ROOT

TOOLS_DIR = PROJECT_ROOT / "tools"
MAX_MANIFEST_BYTES = 64 * 1024


@dataclass(frozen=True)
class ManifestError:
    file: str
    message: str


@dataclass
class Catalog:
    tools: list[ToolManifest] = field(default_factory=list)
    errors: list[ManifestError] = field(default_factory=list)

    def get(self, tool_id: str) -> ToolManifest | None:
        return next((t for t in self.tools if t.id == tool_id), None)

    @property
    def reviewed(self):
        return max((t.review_date for t in self.tools), default=None)


def load_catalog(directory: Path = TOOLS_DIR) -> Catalog:
    catalog = Catalog()
    seen: dict[str, str] = {}
    for path in sorted(directory.rglob("*.yaml")):
        try:
            if path.stat().st_size > MAX_MANIFEST_BYTES:
                raise ValueError(f"file is larger than {MAX_MANIFEST_BYTES // 1024} KB")
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("expected a mapping at the top level")
            tool = ToolManifest.model_validate(data)
        except ValidationError as exc:
            catalog.errors.append(ManifestError(path.name, _first_error(exc)))
            continue
        except (OSError, ValueError, yaml.YAMLError) as exc:
            catalog.errors.append(ManifestError(path.name, str(exc).splitlines()[0]))
            continue
        if tool.id in seen:
            catalog.errors.append(ManifestError(path.name, f"duplicate id '{tool.id}' (also in {seen[tool.id]})"))
            continue
        if path.stem != tool.id:
            catalog.errors.append(ManifestError(path.name, f"file name must match id ('{tool.id}.yaml')"))
            continue
        seen[tool.id] = path.name
        catalog.tools.append(tool)
    catalog.tools.sort(key=lambda t: (list(Category).index(t.category), t.name.lower()))
    return catalog


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    where = ".".join(str(part) for part in error["loc"]) or "manifest"
    return f"{where}: {error['msg']}".replace("Value error, ", "")


# ---------------------------------------------------------------- filters

BEHAVIORS = ("any", "local", "external", "active")


def filter_tools(
    tools: Iterable[ToolManifest],
    query: str = "",
    category: Category | str | None = None,
    behavior: str = "any",
    open_source_only: bool = False,
) -> list[ToolManifest]:
    """Filter by name/text, category, local/external/active behavior and open-source status."""
    words = query.lower().split()
    wanted = Category(category) if category else None
    result = []
    for tool in tools:
        if wanted and tool.category is not wanted:
            continue
        if behavior == "local" and Label.LOCAL not in tool.labels:
            continue
        if behavior == "external" and Label.EXTERNAL not in tool.labels:
            continue
        if behavior == "active" and Label.ACTIVE not in tool.labels:
            continue
        if open_source_only and not tool.open_source:
            continue
        haystack = " ".join(
            [tool.id, tool.name, tool.description, tool.category.label, tool.license or "", tool.short_url]
        ).lower()
        if all(word in haystack for word in words):
            result.append(tool)
    return result


# ---------------------------------------------------------------- availability


@dataclass(frozen=True)
class Availability:
    status: str   # shown in the library row
    ready: bool   # can be used right now (later: by the runner)
    detail: str


def availability(tool: ToolManifest, db: Database | None = None, root: Path = PROJECT_ROOT) -> Availability:
    if tool.is_active and not (db is not None and db.get_setting(tool.active_setting, False)):
        return Availability("Disabled", False, "Active tool: off until enabled in Settings, and checked "
                                               "against the case's authorized scope.")
    launch = tool.launch
    if launch.kind is LaunchKind.BROWSER:
        return Availability("Opens browser", True, "Opens the official site; nothing runs on this computer.")
    if launch.kind is LaunchKind.WEB_API:
        if tool.api_key == "required":
            return Availability("Needs key", False, "Needs an API key. Keys are stored in Windows "
                                                    "Credential Manager (Settings, week 5).")
        return Availability("Web API", True, "Called over HTTPS by a built-in module, after consent.")
    if launch.kind is LaunchKind.PYTHON:
        if importlib.util.find_spec(launch.module) is not None:
            return Availability("Built in", True, f"Python library '{launch.module}' is installed.")
        return Availability("Not installed", False, f"Python library '{launch.module}' is not installed yet.")
    target = root / (launch.venv + "/Scripts/python.exe" if launch.venv else launch.executable)
    if target.is_file() and (not launch.script or (root / launch.script).is_file()):
        problem = integrity_problem(tool, root) if launch.sha256 else None
        if problem:
            return Availability("Integrity check failed", False, problem)
        if not launch.args:
            return Availability("Not integrated", False, "Installed, but no module runs it yet.")
        return Availability("Installed", True, f"Found {target.relative_to(root).as_posix()}.")
    where = launch.venv or launch.executable
    return Availability("Not installed", False, f"Expected at {where}. Tool environments are set up with "
                                                "the runner (week 4).")


_integrity: dict[tuple[str, object], str | None] = {}


def integrity_problem(tool: ToolManifest, root: Path = PROJECT_ROOT) -> str | None:
    """Pinned-hash check of a bin/ tool, once per process (startup). Every run checks it again."""
    key = (str(root), tool.launch)
    if key not in _integrity:
        from core.runner import CommandError, tool_program  # runner pulls in Qt

        try:
            tool_program(tool, root)
            _integrity[key] = None
        except CommandError as exc:
            _integrity[key] = str(exc)
    return _integrity[key]


# ---------------------------------------------------------------- database


def sync_tools(db: Database, tools: Iterable[ToolManifest]) -> None:
    """Mirror the catalog into the tools table (runs reference tools by id)."""
    tools = list(tools)
    rows = [
        (
            t.id,
            t.name,
            t.category.value,
            t.official_url,
            t.license,
            int(t.open_source),
            json.dumps([label.value for label in t.labels]),
            {"none": None, "optional": "API key optional", "required": "API key required"}[t.api_key],
            t.launch.kind.value,
            t.review_date.isoformat(),
        )
        for t in tools
    ]
    with db.transaction() as conn:
        conn.executemany(
            """
            INSERT INTO tools (id, name, category, official_url, license, open_source, labels,
                               api_requirements, launch_method, review_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name, category = excluded.category,
                official_url = excluded.official_url, license = excluded.license,
                open_source = excluded.open_source, labels = excluded.labels,
                api_requirements = excluded.api_requirements,
                launch_method = excluded.launch_method, review_date = excluded.review_date
            """,
            rows,
        )
        ids = [t.id for t in tools]
        placeholders = ",".join("?" * len(ids)) or "''"
        conn.execute(f"DELETE FROM tools WHERE id NOT IN ({placeholders})", ids)
