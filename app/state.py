"""Shared UI state: the database, the case manager and the active case."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

from core.catalog import TOOLS_DIR, Catalog, load_catalog, sync_tools
from core.cases import Case, CaseManager, CaseNotFound
from core.db import Database
from core.evidence import EvidenceStore
from core.findings import FindingStore
from core.modules import ModuleSpec, discover
from core.net import ApiCache, Http
from core.runs import ConsentLog, RunStore
from core.secrets import KeyStore


class AppState(QObject):
    navigate_requested = Signal(str)
    active_case_changed = Signal(object)  # Case | None
    cases_changed = Signal()
    catalog_changed = Signal(object)  # Catalog
    tab_requested = Signal(str)       # case workspace tab key
    settings_changed = Signal()
    target_preset = Signal(object)    # Target picked in the quick lookup
    message = Signal(str)

    def __init__(self, db: Database, manager: CaseManager | None = None, tools_dir=TOOLS_DIR,
                 keys: KeyStore | None = None, data_root=None):
        super().__init__()
        from app.runs import RunController

        self.db = db
        self.cases = manager or CaseManager(db)
        self.findings = FindingStore(db)
        self.run_store = RunStore(db, data_root)
        self.consents = ConsentLog(db)
        self.evidence = EvidenceStore(db, data_root)
        self.keys = keys or KeyStore()
        self.modules: list[ModuleSpec] = discover()
        self.runner = RunController(self)
        self._active: Case | None = None
        self._tools_dir = tools_dir
        self.catalog: Catalog = Catalog()
        self.reload_catalog()
        self.run_store.fail_interrupted()

    def module(self, module_id: str) -> ModuleSpec:
        return next(m for m in self.modules if m.id == module_id)

    def services(self, spec: ModuleSpec) -> dict:
        """What a python module may use. Only its own API key is handed over; no DB connection."""
        cache = ApiCache(self.db.cache_path, bool(self.db.get_setting("cache_external_results", True)))
        services = {
            "http_factory": lambda check: Http(cache, check),
            "settings": {key: self.db.get_setting(key) for key in ("active.port_scan",)},
        }
        if spec.api_key:
            services["api_key"] = self.keys.get(spec.api_key)
        return services

    def reload_catalog(self) -> Catalog:
        """Re-read tools/*.yaml and mirror valid manifests into the tools table."""
        return self.set_catalog(load_catalog(self._tools_dir))

    def reload_catalog_in_background(self, on_done: Callable[[Catalog | None, BaseException | None], None]) -> None:
        """Parse the manifests (~0.7 s for 400) on the thread pool; the DB sync and signal run on the GUI thread."""
        def done(catalog, error) -> None:
            on_done(self.set_catalog(catalog) if error is None else None, error)

        tools_dir = self._tools_dir
        run_in_background(lambda: load_catalog(tools_dir), done)

    def set_catalog(self, catalog: Catalog) -> Catalog:
        self.catalog = catalog
        sync_tools(self.db, catalog.tools)
        self.catalog_changed.emit(catalog)
        return catalog

    @property
    def active_case(self) -> Case | None:
        return self._active

    def restore_last_case(self) -> None:
        case_id = self.db.get_setting("last_case_id")
        if case_id is None:
            return
        try:
            self._active = self.cases.get_case(case_id)
        except CaseNotFound:
            self.db.set_setting("last_case_id", None)
            return
        self.active_case_changed.emit(self._active)

    def open_case(self, case_id: int, navigate: bool = True) -> None:
        self._active = self.cases.get_case(case_id)
        self.db.set_setting("last_case_id", case_id)
        self.active_case_changed.emit(self._active)
        if navigate:
            self.navigate_requested.emit("case")

    def case_updated(self, case: Case) -> None:
        """Call after any change to a case so every view refreshes."""
        if self._active is not None and self._active.id == case.id:
            self._active = case
            self.active_case_changed.emit(case)
        self.cases_changed.emit()

    def preset_target(self, target) -> None:
        self.target_preset.emit(target)
        self.navigate_requested.emit("modules")

    def request_tab(self, key: str) -> None:
        self.tab_requested.emit(key)

    def case_deleted(self) -> None:
        self._active = None
        self.active_case_changed.emit(None)
        self.cases_changed.emit()
        self.navigate_requested.emit("dashboard")

    def navigate(self, key: str) -> None:
        self.navigate_requested.emit(key)

    def say(self, text: str) -> None:
        self.message.emit(text)


class _TaskSignals(QObject):
    done = Signal(object, object)  # result, exception

    def __init__(self, on_done: Callable[[object, BaseException | None], None]):
        super().__init__()
        self._on_done = on_done
        self.done.connect(self._deliver)  # this object lives on the GUI thread, so delivery is queued there

    @Slot(object, object)
    def _deliver(self, result, error) -> None:
        _pending.discard(self)
        self._on_done(result, error)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], object], signals: _TaskSignals):
        super().__init__()
        self._fn, self._signals = fn, signals

    def run(self) -> None:
        try:
            result, error = self._fn(), None
        except Exception as exc:  # handed to on_done, which reports it
            result, error = None, exc
        self._signals.done.emit(result, error)


_pending: set[_TaskSignals] = set()


def run_in_background(fn: Callable[[], object], on_done: Callable[[object, BaseException | None], None]) -> None:
    """Run slow file or process work (hashing, copying, cipher) on the thread pool; on_done(result, error)
    then runs on the GUI thread. fn must not touch the database: the sqlite connection is GUI-thread only."""
    signals = _TaskSignals(on_done)
    _pending.add(signals)  # keep it alive until the result is delivered
    QThreadPool.globalInstance().start(_Task(fn, signals))
