"""Run flow through the UI: gates, consent dialog + log, run console, findings workflow."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QColor, QImage

from app.dialogs import ConsentDialog, EvidenceDialog, Notice
from app.main_window import MainWindow
from app.run_flow import launch_module
from app.state import AppState
from core.cases import LookupMode
from core.db import Database
from core.findings import Finding, FindingStatus
from core.modules import ALL_ENGINES, Engine, ModuleSpec
from core.paths import PROJECT_ROOT
from core.runs import evidence_lines
from core.secrets import KeyStore, MemoryKeyring
from core.validation import TargetType


def fake_external(ctx):
    ctx.emit(f"[+] Example: https://example.com/{ctx.target}")
    return [Finding(module="FakeRecon", title="Example profile", source="fake",
                    url=f"https://example.com/{ctx.target}")]


FAKE_EXTERNAL = ModuleSpec(number="90", id="fakerecon", name="FakeRecon", icon="user", description="test only",
                           labels=("external", "passive"), target_types=(TargetType.USERNAME,),
                           provider="example.com (test)", run=fake_external, timeout_s=10)
FAKE_ACTIVE = ModuleSpec(number="91", id="fakeactive", name="FakeActive", icon="port", description="test only",
                         labels=("active",), target_types=(TargetType.IP,), provider="the target host",
                         active_setting="active.port_scan", run=lambda ctx: [], timeout_s=10)


@pytest.fixture
def app_window(qtbot, themed_app, db_path, new_case):
    db = Database(db_path)
    state = AppState(db, keys=KeyStore(MemoryKeyring()))
    state.modules += [FAKE_EXTERNAL, FAKE_ACTIVE]
    window = MainWindow(state, str(db_path.parent))
    qtbot.addWidget(window)
    window.resize(1400, 900)
    window.show()
    case = state.cases.create_case(new_case(authorized_scope="My lab 192.0.2.0/24, example.com, example_user"))
    state.open_case(case.id)
    yield window, state, case
    window.close()
    db.close()


def wait_for_run(qtbot, state, start):
    with qtbot.waitSignal(state.runner.finished, timeout=60000) as blocker:
        assert start()
    return blocker.args[0]


def test_consent_cancel_sends_nothing(app_window, monkeypatch):
    window, state, case = app_window
    target = state.cases.list_targets(case.id)[0]
    monkeypatch.setattr(ConsentDialog, "exec", lambda self: 0)
    assert not launch_module(window, state, FAKE_EXTERNAL, target=target)
    assert state.consents.list(case.id) == []
    assert state.run_store.list(case.id) == []


def test_external_run_logs_consent_and_saves_leads(qtbot, app_window, monkeypatch):
    window, state, case = app_window
    target = state.cases.list_targets(case.id)[0]
    seen = {}

    def accept(dialog):
        seen["ok_enabled_before"] = dialog.ok.isEnabled()
        dialog.scope_box.setChecked(True)
        seen["ok_enabled_after"] = dialog.ok.isEnabled()
        return 1

    monkeypatch.setattr(ConsentDialog, "exec", accept)
    run = wait_for_run(qtbot, state, lambda: launch_module(window, state, FAKE_EXTERNAL, target=target))
    assert seen == {"ok_enabled_before": False, "ok_enabled_after": True}  # scope must be confirmed
    assert run.run.status == "succeeded"
    [consent] = state.consents.list(case.id)
    assert (consent.run_id, consent.data_sent, consent.scope_confirmed) == (run.run.id, "example_user", True)

    assert window.current_key() == "run"
    console = window.screens["run"].console.toPlainText()
    assert "consent #C-0001 logged" in console
    assert "[+] Example: https://example.com/example_user" in console
    assert "lead saved to CASE-001" in console

    [finding] = state.findings.list(case.id)
    assert finding.status is FindingStatus.LEAD
    workspace = window.screens["case"]
    window.screens["run"]._open_case()
    assert window.current_key() == "case" and workspace.tabs.current() == "findings"
    panel = workspace.findings_panel
    assert panel.selected_id == finding.id
    panel.d_note.setPlainText("Matches my own account.")
    panel.btn_verify.click()
    assert state.findings.get(finding.id).status is FindingStatus.VERIFIED
    assert workspace.stat_leads.value.text() == "0"


def test_active_module_is_blocked_by_default(app_window, monkeypatch):
    window, state, case = app_window
    shown = {}
    monkeypatch.setattr(Notice, "exec", lambda self: shown.setdefault("notice", True) and 0)
    monkeypatch.setattr(ConsentDialog, "exec", lambda self: pytest.fail("no consent before gates pass"))
    target = state.cases.add_target(case.id, "ip", "192.0.2.10")
    assert not launch_module(window, state, FAKE_ACTIVE, target=target)
    assert shown == {"notice": True}
    assert state.run_store.list(case.id) == []


def test_active_module_needs_fresh_consent_every_time(qtbot, app_window, monkeypatch, new_case):
    window, state, _ = app_window
    state.db.set_setting("active.port_scan", True)
    case = state.cases.create_case(new_case(
        authorized_scope="Lab 192.0.2.0/24", allowed_modes=[LookupMode.LOCAL, LookupMode.ACTIVE],
        first_target_type="ip", first_target_value="192.0.2.10"))
    state.open_case(case.id)
    target = state.cases.list_targets(case.id)[0]

    def accept(dialog):
        assert dialog.active and not dialog.remember_box.isVisible()
        dialog.scope_box.setChecked(True)
        assert not dialog.ok.isEnabled()  # also needs the ownership box
        dialog.owner_box.setChecked(True)
        return 1

    monkeypatch.setattr(ConsentDialog, "exec", accept)
    run = wait_for_run(qtbot, state, lambda: launch_module(window, state, FAKE_ACTIVE, target=target))
    assert run.run.active and run.consent.active


@pytest.mark.skipif(not (PROJECT_ROOT / "bin" / "exiftool.exe").is_file(), reason="ExifTool not installed")
def test_local_imagemeta_run(qtbot, app_window, tmp_path, monkeypatch):
    window, state, case = app_window
    monkeypatch.setattr(ConsentDialog, "exec", lambda self: pytest.fail("local modules need no consent"))
    image = QImage(32, 24, QImage.Format.Format_RGB32)
    image.fill(QColor("#9a8cff"))
    sample = tmp_path / "profile_01.jpg"
    image.save(str(sample), "JPG")
    target = state.cases.add_target(case.id, "file", str(sample))
    spec = state.module("imagemeta")
    run = wait_for_run(qtbot, state, lambda: launch_module(window, state, spec, target=target))
    assert run.run.status == "succeeded", run.outcome.error
    assert run.consent is None
    titles = {f.title for f in state.findings.list(case.id)}
    assert {"SHA-256", "File type", "No GPS data"} <= titles
    assert (state.run_store.get(run.run.id).log_path or "").endswith("run.log")
    screen = window.screens["run"]
    assert screen.table.rowCount() == len(titles)
    assert "Finished" in screen.status_text.text()


class FakeRunner(QObject):
    finished = Signal(object)

    def __init__(self):
        super().__init__()
        self.started = []
        self.current = None
        self.busy = False

    def stop(self):
        pass

    def problems(self, spec, case, target, engine_id=None):
        return []

    def start(self, spec, case, target, consent, engine_id):
        self.started.append((engine_id, consent.id))


def ended(status):
    return SimpleNamespace(run=SimpleNamespace(status=status))


@pytest.fixture
def two_engines(app_window, monkeypatch):
    window, state, case = app_window
    ready = [Engine(name, name, None, ("external", "passive"), "example.com (test)", None, True, "") for name in ("one", "two")]
    monkeypatch.setattr("app.run_flow.engines", lambda *args: ready)
    monkeypatch.setattr(state, "runner", FakeRunner())
    monkeypatch.setattr(ConsentDialog, "exec", lambda self: 1)
    return window, state, state.cases.list_targets(case.id)[0]


def test_all_engines_run_one_after_another_with_a_consent_each(qtbot, two_engines):
    window, state, target = two_engines
    assert launch_module(window, state, FAKE_EXTERNAL, target=target, engine_id=ALL_ENGINES)
    assert [engine for engine, _ in state.runner.started] == ["one"]
    state.runner.finished.emit(ended("succeeded"))
    qtbot.waitUntil(lambda: len(state.runner.started) == 2)
    [first, second] = state.runner.started
    assert second[0] == "two" and first[1] != second[1]  # each tool has its own logged consent
    state.runner.finished.emit(ended("succeeded"))  # the chain is done: nothing else starts
    qtbot.wait(20)
    assert len(state.runner.started) == 2


def test_stopping_ends_the_whole_chain(qtbot, two_engines):
    window, state, target = two_engines
    launch_module(window, state, FAKE_EXTERNAL, target=target, engine_id=ALL_ENGINES)
    state.runner.finished.emit(ended("cancelled"))
    qtbot.wait(20)
    assert [engine for engine, _ in state.runner.started] == ["one"]


def test_cancelling_a_consent_starts_nothing(two_engines, monkeypatch):
    window, state, target = two_engines
    monkeypatch.setattr(ConsentDialog, "exec", lambda self: 0)
    assert not launch_module(window, state, FAKE_EXTERNAL, target=target, engine_id=ALL_ENGINES)
    assert state.runner.started == []


def test_evidence_shows_the_raw_line_and_the_source(qtbot, app_window, monkeypatch):
    window, state, case = app_window
    target = state.cases.list_targets(case.id)[0]
    monkeypatch.setattr(ConsentDialog, "exec", lambda self: 1)
    run = wait_for_run(qtbot, state, lambda: launch_module(window, state, FAKE_EXTERNAL, target=target))
    [finding] = state.findings.list(case.id, run_id=run.run.id)
    assert evidence_lines(Path(run.run.log_path), finding) == ["[+] Example: https://example.com/example_user"]
    dialog = EvidenceDialog(window, finding, run.run)
    qtbot.addWidget(dialog)
    assert "[+] Example: https://example.com/example_user" in dialog.raw.toPlainText()

    opened = []
    monkeypatch.setattr(EvidenceDialog, "exec", lambda self: opened.append(self.finding.id))
    screen = window.screens["run"]
    screen._fill_table(run)
    screen._cell_clicked(0, 1)  # other columns open nothing
    screen._cell_clicked(0, 4)
    assert opened == [finding.id]


def test_evidence_explains_a_finding_with_no_log_line(qtbot, app_window):
    window, state, case = app_window
    finding = state.findings.get(state.findings.add(case.id, [Finding(module="FakeRecon", title="Note", source="fake",
                                                                      value="no such line")], None, None)[0])
    dialog = EvidenceDialog(window, finding, None)
    qtbot.addWidget(dialog)
    assert "No matching line" in dialog.raw.toPlainText()
