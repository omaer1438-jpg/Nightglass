"""UI fixes from the Phase 1 audit: retention confirm, EFS off the GUI thread, gates, settings that work."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QLabel, QWidget

from app.dialogs import Modal, Notice
from app.main_window import MainWindow
from app.state import AppState
from app.widgets import EmptyState
from core.db import Database
from core.findings import Finding
from core.modules import ModuleSpec
from core.validation import TargetType

FAKE_LOCAL = ModuleSpec(number="92", id="fakelocal", name="FakeLocal", icon="user", description="test only",
                        labels=("local",), target_types=(TargetType.USERNAME,), provider="this computer",
                        run=lambda ctx: [Finding(module="FakeLocal", title="Example", source="fake")], timeout_s=10)


@pytest.fixture
def ui(qtbot, themed_app, db_path, new_case):
    db = Database(db_path)
    state = AppState(db)
    state.modules.append(FAKE_LOCAL)
    window = MainWindow(state, str(db_path.parent))
    qtbot.addWidget(window)
    window.resize(1564, 964)
    window.show()
    case = state.cases.create_case(new_case())
    state.open_case(case.id)
    messages: list[str] = []
    state.message.connect(messages.append)
    yield window, state, case, messages
    window.close()
    db.close()


def answer_notice(monkeypatch, take: bool, seen: list):
    def fake_exec(self):
        seen.append(self)
        self.action_taken = take
        return 1
    monkeypatch.setattr(Notice, "exec", fake_exec)


def test_retention_change_asks_counts_and_spares_custom_cases(ui, monkeypatch, new_case):
    window, state, case, messages = ui
    db = state.db
    old = state.cases.create_case(new_case(name="Old closed case"))
    custom = state.cases.create_case(new_case(name="Kept on purpose"))
    state.cases.close_case(old.id)
    long_ago = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat(timespec="seconds")
    db.execute("UPDATE cases SET closed_at = ? WHERE id = ?", (long_ago, old.id))
    db.execute("UPDATE cases SET retention_days = 180 WHERE id = ?", (custom.id,))
    screen = window.screens["settings"]

    seen: list[Notice] = []
    answer_notice(monkeypatch, take=False, seen=seen)
    screen.retention.setCurrentIndex(screen.retention.findData(30))
    assert db.get_setting("retention_days") == 90 and screen.retention.currentData() == 90  # cancelled: reverted
    text = " ".join(lbl.text() for lbl in seen[-1].findChildren(QLabel))
    assert "1 closed case(s)" in text and "2 existing case(s)" in text

    answer_notice(monkeypatch, take=True, seen=seen)
    screen.retention.setCurrentIndex(screen.retention.findData(30))
    assert db.get_setting("retention_days") == 30
    assert state.cases.get_case(old.id).retention_days == 30
    assert state.cases.get_case(case.id).retention_days == 30
    assert state.cases.get_case(custom.id).retention_days == 180  # its own value is kept

    screen.retention.setCurrentIndex(screen.retention.findData(None))  # "Never"
    assert db.get_setting("retention_days") is None
    assert "No closed case" in " ".join(lbl.text() for lbl in seen[-1].findChildren(QLabel))


def test_efs_runs_off_the_gui_thread(qtbot, ui, monkeypatch):
    window, state, case, messages = ui
    calls = []

    def slow_cipher(folder, on):
        time.sleep(0.3)
        calls.append(on)
        return False, "Windows EFS failed: test"

    monkeypatch.setattr("app.screens.settings.set_efs", slow_cipher)
    answer_notice(monkeypatch, take=True, seen=[])
    screen = window.screens["settings"]
    screen.efs.setChecked(True)
    assert not screen.efs.isEnabled() and calls == []  # returned at once, busy until cipher ends
    qtbot.waitUntil(lambda: screen.efs.isEnabled(), timeout=5000)
    assert calls == [True]
    assert not screen.efs.isChecked()  # failure reverts the switch
    assert messages[-1] == "Windows EFS failed: test"


def test_encryption_switch_refused_while_a_run_is_going(ui, monkeypatch):
    window, state, case, messages = ui
    monkeypatch.setattr(type(state.runner), "busy", property(lambda self: True))
    screen = window.screens["settings"]
    screen.encrypt.setChecked(True)
    assert not screen.encrypt.isChecked() and not state.db.encrypted
    assert "still running" in messages[-1]
    monkeypatch.setattr("app.screens.settings.set_efs", lambda *a: pytest.fail("EFS must not run during a run"))
    screen.efs.setChecked(True)
    assert not screen.efs.isChecked() and "still running" in messages[-1]


def test_active_counter_counts_every_active_switch(ui):
    window, state, case, messages = ui
    for key in ("active.wafw00f", "active.zone_transfer"):
        state.db.set_setting(key, True)
    state.settings_changed.emit()
    assert window.sidebar.active_label.text().endswith("Active modules: 2 on")


def test_new_case_errors_cleared_on_next_visit(ui):
    window, state, case, messages = ui
    window.navigate("newcase")
    screen = window.screens["newcase"]
    screen.create_case()
    assert screen.f_name.error.isVisibleTo(screen)
    window.navigate("dashboard")
    window.navigate("newcase")
    assert not screen.f_name.error.isVisibleTo(screen)


def test_results_view_setting_picks_the_run_console_view(qtbot, ui):
    window, state, case, messages = ui
    state.db.set_setting("results_view", "table")
    target = state.cases.list_targets(case.id)[0]
    with qtbot.waitSignal(state.runner.finished, timeout=10000):
        state.runner.start(FAKE_LOCAL, case, target, None)
    console = window.screens["run"]
    assert console.view_toggle.current() == "table" and console.output.currentIndex() == 1


def test_modal_dims_the_window_while_open(qtbot, ui):
    window, state, case, messages = ui
    seen = []
    dialog = Modal(window)
    qtbot.addWidget(dialog)

    def check():
        seen.extend(w for w in window.findChildren(QWidget) if w.objectName() == "ModalScrim" and w.isVisible())
        dialog.reject()

    QTimer.singleShot(0, check)
    dialog.exec()
    assert len(seen) == 1 and seen[0].geometry() == window.rect()
    assert not any(w.objectName() == "ModalScrim" and w.isVisible() for w in window.findChildren(QWidget))


def test_empty_state_text_gets_its_wrapped_height(qtbot, themed_app):
    empty = EmptyState("case", "No cases yet", "Every case starts with a purpose and an authorized scope. "
                       "Create one to start collecting leads, and come back here later to review them.")
    qtbot.addWidget(empty)
    empty.resize(900, 300)
    empty.show()
    qtbot.waitExposed(empty)
    body = next(lbl for lbl in empty.findChildren(QLabel) if lbl.wordWrap())
    assert body.width() == 460
    assert body.height() >= body.heightForWidth(body.width()) > body.fontMetrics().height()


def test_modules_grid_never_scrolls_sideways(qtbot, ui):
    window, state, case, messages = ui
    window.navigate("modules")
    screen = window.screens["modules"]
    for mode in ("modules", "links"):
        screen.source_toggle.buttons[mode].click()
        qtbot.wait(50)
        assert screen.horizontalScrollBar().maximum() == 0, mode
