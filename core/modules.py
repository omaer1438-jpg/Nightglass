"""Built-in modules (plan section 4): registry, availability and safety gates.

A module is defined by an adapter in adapters/ that exposes MODULE = ModuleSpec(...).
Tool modules run a catalog tool as a subprocess and parse its output; python
modules run a function on a worker thread. Adding a module needs no core changes.
"""

from __future__ import annotations

import importlib
import ipaddress
import pkgutil
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from core.cases import Case, LookupMode
from core.catalog import Catalog, availability
from core.db import Database
from core.findings import Finding
from core.manifest import ToolManifest
from core.validation import TargetType, ValidationError, validate_target

if TYPE_CHECKING:
    from core.runner import ModuleContext


@dataclass(frozen=True)
class ParseResult:
    findings: list[Finding]
    counts: dict[str, int] = field(default_factory=dict)  # e.g. found / uncertain / not_found


@dataclass(frozen=True)
class ModuleSpec:
    number: str
    id: str
    name: str
    icon: str
    description: str
    labels: tuple[str, ...]
    target_types: tuple[TargetType, ...]
    provider: str                                   # "Sent to", shown in the consent dialog
    tools: tuple[str, ...] = ()                     # catalog tool ids, first installed one is used
    run: Callable[[ModuleContext], list[Finding]] | None = None
    console_tag: Callable[[str], str] | None = None
    timeout_s: int = 60
    max_output_kb: int = 1024
    active_setting: str | None = None
    api_key: str | None = None                      # keyring entry name
    api_key_required: bool = False
    notes: str = ""
    engine_name: str = "Built-in"                   # label of the python implementation in the picker
    needs_tool: str | None = None                   # catalog tool the built-in code launches itself (Osintgram)

    @property
    def is_external(self) -> bool:
        """Anything not purely local sends data off this computer and needs consent."""
        return "local" not in self.labels

    @property
    def is_active(self) -> bool:
        return "active" in self.labels

    @property
    def title(self) -> str:
        return f"{self.number} {self.name}"


def discover() -> list[ModuleSpec]:
    import adapters

    specs = []
    for info in pkgutil.iter_modules(adapters.__path__):
        module = importlib.import_module(f"adapters.{info.name}")
        spec = getattr(module, "MODULE", None)
        if isinstance(spec, ModuleSpec):
            specs.append(spec)
    return sorted(specs, key=lambda s: s.number)


def parser_for(tool: ToolManifest) -> Callable:
    """The manifest's parser (adapters.<module>:<function>), validated by the schema."""
    module_name, _, func = tool.parser.partition(":")
    return getattr(importlib.import_module(module_name), func)


# ---------------------------------------------------------------- availability


#: Picker value for "run every ready engine".
ALL_ENGINES = "all"


@dataclass(frozen=True)
class Engine:
    """One way to run a module: its built-in code, or one of its catalog tools.

    Consent and gates use the engine's own labels, so choosing an active tool (Holehe)
    gets the full active-module checks even inside a passive module.
    """

    id: str                       # "builtin" or a tool id
    name: str
    tool: ToolManifest | None
    labels: tuple[str, ...]
    provider: str
    active_setting: str | None
    ready: bool
    reason: str

    @property
    def is_external(self) -> bool:
        return "local" not in self.labels

    @property
    def is_active(self) -> bool:
        return "active" in self.labels


def engines(spec: ModuleSpec, catalog: Catalog, db: Database, has_key: Callable[[str], bool]) -> list[Engine]:
    found: list[Engine] = []
    if spec.run is not None:
        ready, reason = True, "Built in."
        if spec.active_setting and not db.get_setting(spec.active_setting, False):
            ready, reason = False, "Active module: enable it in Settings → Active modules first."
        elif spec.api_key and spec.api_key_required and not has_key(spec.api_key):
            ready, reason = False, f"Add the {spec.api_key} API key in Settings first."
        elif spec.needs_tool:
            tool = catalog.get(spec.needs_tool)
            state = availability(tool, db) if tool else None
            if not (state and state.ready):
                ready, reason = False, f"{tool.name if tool else spec.needs_tool}: " + (
                    state.status.lower() if state else "missing from the catalog")
        found.append(Engine("builtin", spec.engine_name, None, spec.labels, spec.provider, spec.active_setting,
                            ready, reason))
    for tool_id in spec.tools:
        tool = catalog.get(tool_id)
        if tool is None:
            continue
        state = availability(tool, db)
        integrated = bool(tool.launch.args and tool.parser)
        ready = state.ready and integrated
        if ready:
            reason = f"Uses {tool.name}."
        elif state.ready:
            reason = f"{tool.name}: not integrated yet"
        else:
            reason = f"{tool.name}: {state.status.lower()}"
        labels = tuple(label.value for label in tool.labels) + (("oss",) if tool.open_source else ())
        found.append(Engine(tool.id, tool.name, tool, labels, tool.provider or spec.provider,
                            tool.active_setting, ready, reason))
    return found


def pick_engine(spec: ModuleSpec, catalog: Catalog, db: Database, has_key: Callable[[str], bool],
                engine_id: str | None = None) -> Engine | None:
    options = [e for e in engines(spec, catalog, db, has_key) if e.ready]
    if engine_id:
        return next((e for e in options if e.id == engine_id), None)
    return options[0] if options else None


@dataclass(frozen=True)
class ModuleStatus:
    ready: bool
    label: str        # short status for the module card
    reason: str       # why it can't run, or what it will use
    tool: ToolManifest | None = None


def module_status(spec: ModuleSpec, catalog: Catalog, db: Database, has_key: Callable[[str], bool]) -> ModuleStatus:
    options = engines(spec, catalog, db, has_key)
    ready = [e for e in options if e.ready]
    if ready:
        names = " or ".join(e.name for e in ready)
        return ModuleStatus(True, "Ready", f"Uses {names}.", ready[0].tool)
    if spec.active_setting and not db.get_setting(spec.active_setting, False):
        return ModuleStatus(False, "Off", "Active module: enable it in Settings → Active modules first.")
    if spec.api_key and spec.api_key_required and not has_key(spec.api_key):
        return ModuleStatus(False, "Needs key", f"Add the {spec.api_key} API key in Settings first.")
    if not options:
        return ModuleStatus(False, "Unavailable", "This module has no implementation yet.")
    return ModuleStatus(False, "Not installed", "Needs one of: " + "; ".join(e.reason for e in options))


# ---------------------------------------------------------------- gates


def _names(text: str, token: str) -> bool:
    """Whole-token match: 192.0.2.1 must not match 192.0.2.10, nor example.com match notexample.com,
    www.example.com or example.com.au. A sentence-ending period or colon is allowed."""
    return re.search(rf"(?<![a-z0-9._@:-]){re.escape(token)}(?![a-z0-9_@-]|[.:][a-z0-9])", text) is not None


def scope_covers(scope: str, target_type: TargetType, value: str) -> bool:
    """Does the case's authorized scope text name this target (or its domain / network)?"""
    text = scope.lower()
    value = value.lower()
    if _names(text, value):
        return True
    if target_type is TargetType.DOMAIN or target_type is TargetType.URL:
        host = re.sub(r"^https?://", "", value).split("/")[0].split(":")[0].strip("[]")
        labels = host.split(".")
        for i in range(len(labels) - 1):
            parent = ".".join(labels[i:])
            if _names(text, parent):
                return True
    if target_type is TargetType.IP:
        address = ipaddress.ip_address(value)
        for token in re.findall(r"[0-9a-f:.]+/\d{1,3}", text):
            try:
                if address in ipaddress.ip_network(token, strict=False):
                    return True
            except ValueError:
                continue
    return False


def check_gates(spec: ModuleSpec, case: Case, target_type: TargetType, target_value: str,
                db: Database, engine: Engine | None = None) -> list[str]:
    """Reasons this run is not allowed. Empty list = allowed. Uses the chosen engine's labels."""
    is_active = engine.is_active if engine else spec.is_active
    is_external = engine.is_external if engine else spec.is_external
    active_setting = (engine.active_setting if engine else None) or spec.active_setting
    problems = []
    if not case.is_open:
        problems.append(f"{case.ref} is closed. Reopen it to run modules.")
    if target_type not in spec.target_types:
        accepted = ", ".join(t.label for t in spec.target_types)
        problems.append(f"{spec.name} accepts: {accepted}.")
        return problems
    try:
        value = validate_target(target_type, target_value)
    except ValidationError as exc:
        problems.append(str(exc))
        return problems
    modes = set(case.allowed_modes)
    if is_active:
        if not db.get_setting(active_setting or "", False):
            problems.append("Active modules are off. Enable this one in Settings first.")
        if LookupMode.ACTIVE not in modes:
            problems.append(f"{case.ref} does not allow active lookups (see its allowed lookup modes).")
        if not scope_covers(case.authorized_scope, target_type, value):
            problems.append(f"{value} is not named in {case.ref}'s authorized scope.")
    elif is_external and LookupMode.EXTERNAL_PASSIVE not in modes:
        problems.append(f"{case.ref} does not allow external lookups (see its allowed lookup modes).")
    elif not is_external and LookupMode.LOCAL not in modes:
        problems.append(f"{case.ref} does not allow local lookups.")
    return problems
