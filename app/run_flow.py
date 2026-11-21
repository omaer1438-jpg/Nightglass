"""Launching a module: target -> gates -> consent (logged) -> run -> Run Console."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QWidget

from app.dialogs import ConsentDialog, Notice, TargetPicker
from app.state import AppState
from core.cases import Case, CaseError, Target
from core.modules import ALL_ENGINES, Engine, ModuleSpec, engines
from core.runner import CommandError
from core.runs import ConsentRecord
from core.validation import ValidationError


def launch_module(parent: QWidget, state: AppState, spec: ModuleSpec, target: Target | None = None,
                  preset: str = "", engine_id: str | None = None) -> bool:
    case = state.active_case
    if case is None:
        notice = Notice(parent, "Open a case first", [
            "Modules always run inside a case, so every result, consent and log is kept with it.",
        ], action=("New case", None))
        notice.exec()
        if notice.action_taken:
            state.navigate("newcase")
        return False

    ready = [e for e in engines(spec, state.catalog, state.db, state.keys.has) if e.ready]
    if target is None or (engine_id is None and len(ready) > 1):
        picker = TargetPicker(parent, spec, case, state.cases.list_targets(case.id), preset, ready,
                              fixed_target=target)
        if not picker.exec():
            return False
        engine_id = picker.engine_id
        target = picker.fixed_target
        if picker.new_target:
            kind, value = picker.new_target
            existing = next((t for t in state.cases.list_targets(case.id) if t.type is kind and t.value == value), None)
            try:
                target = existing or state.cases.add_target(case.id, kind, value, input_source="module")
            except (CaseError, ValidationError) as exc:
                Notice(parent, "Can't add this target", [str(exc)]).exec()
                return False
            state.case_updated(state.cases.get_case(case.id))
            case = state.active_case
        elif picker.selected is not None:
            target = picker.selected

    if engine_id == ALL_ENGINES:
        return _run_all(parent, state, spec, case, target, ready)

    problems = state.runner.problems(spec, case, target, engine_id)
    if problems:
        settings_related = any("Settings" in p for p in problems)
        notice = Notice(parent, f"{spec.name} can't run yet", problems, tone="red" if spec.is_active else "amber",
                        action=("Open settings", None) if settings_related else None)
        notice.exec()
        if notice.action_taken:
            state.navigate("settings")
        return False

    engine = state.runner.engine(spec, engine_id)
    agreed, log_consent = _ask_consent(parent, state, spec, case, target, engine)
    if not agreed:
        return False

    try:
        state.runner.start(spec, case, target, log_consent(), engine.id)
    except CommandError as exc:
        Notice(parent, f"{spec.name} could not start", [str(exc)]).exec()
        return False
    state.navigate("run")
    return True


def _no_consent() -> None:
    return None


def _ask_consent(parent: QWidget, state: AppState, spec: ModuleSpec, case: Case, target: Target,
                 engine: Engine, pending: int = 0) -> tuple[bool, Callable[[], ConsentRecord | None]]:
    """(may it run, a call that logs the consent right before its run). A local engine needs none.

    `pending`: consents asked for but not logged yet (Run all), so the dialog shows the ref it will get.
    """
    if not engine.is_external:
        return True, _no_consent
    remember_key = f"{spec.id}.{engine.id}"
    if not engine.is_active and state.consents.remembered(case.id, remember_key):
        return True, lambda: state.consents.record(case.id, spec.name, engine.provider, target.value,
                                                   scope_confirmed=True, remembered=True)
    ref = f"#C-{int(state.consents.next_ref()[3:]) + pending:04d}"
    dialog = ConsentDialog(parent, spec, case, target, ref, engine)
    if not dialog.exec():
        state.say("Cancelled. Nothing was sent.")
        return False, _no_consent
    if dialog.remember:
        state.consents.remember(case.id, remember_key)
    return True, lambda: state.consents.record(case.id, spec.name, engine.provider, target.value,
                                               scope_confirmed=True, active=engine.is_active)


def _run_all(parent: QWidget, state: AppState, spec: ModuleSpec, case: Case, target: Target,
             ready: list[Engine]) -> bool:
    """Every ready engine, one after another. All consent dialogs come first, so nothing interrupts the
    runs; each consent is logged right before its own run, so a stopped batch leaves none without a run."""
    plan: list[tuple[Engine, Callable[[], ConsentRecord | None]]] = []
    blocked: list[str] = []
    for engine in ready:
        problems = state.runner.problems(spec, case, target, engine.id)
        if problems:
            blocked.append(f"{engine.name}: {problems[0]}")
            continue
        pending = sum(1 for e, _ in plan if e.is_external)
        agreed, log_consent = _ask_consent(parent, state, spec, case, target, engine, pending)
        if not agreed:
            return False
        plan.append((engine, log_consent))
    if not plan:
        Notice(parent, f"{spec.name} can't run yet", blocked).exec()
        return False

    def start_next() -> None:
        engine, log_consent = plan.pop(0)
        state.say(f"{spec.name}: running {engine.name}, {len(plan)} more after it.")
        try:
            state.runner.start(spec, case, target, log_consent(), engine.id)
        except CommandError as exc:
            plan.clear()
            state.runner.finished.disconnect(after_run)
            Notice(parent, f"{engine.name} could not start", [str(exc)]).exec()

    def after_run(run) -> None:
        if run.run.status == "cancelled":  # Stop means stop, not "skip to the next tool"
            plan.clear()
        if plan:
            QTimer.singleShot(0, start_next)
        else:
            state.runner.finished.disconnect(after_run)

    state.runner.finished.connect(after_run)
    start_next()
    state.navigate("run")
    return True
