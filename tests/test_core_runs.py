"""Run controller edge cases (WP1): case deleted mid-run, failure reasons, timeout cap, Run-all consents."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal

from app.run_flow import launch_module
from app.runs import ActiveRun
from app.state import AppState
from core.catalog import load_catalog
from core.db import Database
from core.findings import Finding
from core.modules import ALL_ENGINES, Engine, ModuleSpec
from core.retention import delete_case
from core.runner import RunOutcome
from core.secrets import KeyStore, MemoryKeyring
from core.validation import TargetType

release = threading.Event()


def waits_then_finds(ctx):
    release.wait(10)
    return [Finding(module="FakeLocal", title="Example profile", source="fake", url="https://example.com/example_user")]


FAKE_LOCAL = ModuleSpec(number="92", id="fakelocal", name="FakeLocal", icon="user", description="test only",
                        labels=("local",), target_types=(TargetType.USERNAME,), provider="this computer",
                        run=waits_then_finds, timeout_s=120)


@pytest.fixture
def state_case(qapp, db_path, new_case):
    db = Database(db_path)
    state = AppState(db, keys=KeyStore(MemoryKeyring()))
    state.modules.append(FAKE_LOCAL)
    case = state.cases.create_case(new_case())
    release.clear()
    yield state, case, state.cases.list_targets(case.id)[0]
    release.set()
    db.close()


def test_deleting_the_case_mid_run_still_finishes_the_run(qtbot, state_case):
    state, case, target = state_case
    state.runner.start(FAKE_LOCAL, case, target, None)
    assert state.runner.has_active_run(case.id) and not state.runner.has_active_run(case.id + 1)
    delete_case(state.db, case.id)
    with qtbot.waitSignal(state.runner.finished, timeout=10000) as blocker:
        release.set()
    run: ActiveRun = blocker.args[0]
    assert run.run.status == "failed" and "Could not save the findings" in run.run.error
    assert not state.runner.busy and not state.runner.has_active_run(case.id)


def test_default_timeout_setting_caps_every_run(qtbot, state_case):
    state, case, target = state_case
    state.db.set_setting("timeout_cap_s", 60)
    run = state.runner.start(FAKE_LOCAL, case, target, None)
    assert run.timeout_s == 60  # the module asks for 120
    with qtbot.waitSignal(state.runner.finished, timeout=10000):
        release.set()


def test_tool_default_timeout_is_not_capped(qtbot, state_case):
    state, case, target = state_case
    assert state.db.get_setting("timeout_cap_s", 0) == 0  # fresh database: each tool's own limit
    run = state.runner.start(FAKE_LOCAL, case, target, None)
    assert run.timeout_s == 120
    with qtbot.waitSignal(state.runner.finished, timeout=10000):
        release.set()


@pytest.mark.parametrize("status, error", [("timed_out", "Stopped after the 300 s timeout."),
                                           ("failed", "python.exe exited with code 1.")])
def test_a_parse_error_keeps_the_real_failure_reason(qtbot, state_case, monkeypatch, status, error):
    state, case, target = state_case
    tool = load_catalog().get("sherlock")
    record = state.run_store.create(case.id, "UserRecon", target_id=target.id, tool_id=tool.id)

    def broken(lines, work_dir, value):
        raise ValueError("substring not found")

    monkeypatch.setattr("app.runs.parser_for", lambda tool: broken)
    state.runner.current = ActiveRun(FAKE_LOCAL, case, target, record, tool, None, None, 300, 1024)
    state.runner._on_finished(RunOutcome(status=status, lines=["[*] partial line"], error=error))
    run = state.run_store.get(record.id)
    assert (run.status, run.error) == (status, error)


class FakeRunner(QObject):
    finished = Signal(object)

    def __init__(self):
        super().__init__()
        self.started = []

    def problems(self, *args, **kwargs):
        return []

    def start(self, spec, case, target, consent, engine_id):
        self.started.append(consent)


def test_run_all_logs_each_consent_with_its_own_run(qtbot, state_case, monkeypatch):
    state, case, target = state_case
    refs = []

    class Dialog:
        remember = False

        def __init__(self, parent, spec, case, target, ref, engine):
            refs.append(ref)

        def exec(self):
            return 1

    ready = [Engine(n, n, None, ("external", "passive"), "example.com (test)", None, True, "") for n in ("one", "two")]
    monkeypatch.setattr("app.run_flow.engines", lambda *args: ready)
    monkeypatch.setattr("app.run_flow.ConsentDialog", Dialog)
    monkeypatch.setattr(state, "runner", FakeRunner())
    spec = SimpleNamespace(id="fakerecon", name="FakeRecon", is_active=False)
    state.open_case(case.id, navigate=False)
    assert launch_module(None, state, spec, target=target, engine_id=ALL_ENGINES)
    assert refs == ["#C-0001", "#C-0002"]  # each dialog shows the ref its consent will get
    assert len(state.consents.list(case.id)) == 1  # only the run that started has a consent
    state.runner.finished.emit(SimpleNamespace(run=SimpleNamespace(status="cancelled")))
    qtbot.wait(20)
    assert len(state.consents.list(case.id)) == 1  # stopped: the second consent is never logged
    assert [c.ref for c in state.runner.started] == ["#C-0001"]
