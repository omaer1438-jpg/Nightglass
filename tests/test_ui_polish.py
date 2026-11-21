"""Phase 4 polish: shortcuts, empty states, busy states, fix-it messages and big-case speed. Fake data only."""

from __future__ import annotations

import time

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QLabel, QPushButton

from app.dialogs import Notice
from app.main_window import MainWindow
from app.state import AppState
from core.db import Database
from core.findings import Finding, ResultKind


@pytest.fixture
def ui(qtbot, themed_app, db_path, new_case):
    db = Database(db_path)
    state = AppState(db)
    window = MainWindow(state, str(db_path.parent))
    qtbot.addWidget(window)
    window.resize(1480, 940)
    window.show()
    window.activateWindow()
    qtbot.waitUntil(window.isActiveWindow)
    case = state.cases.create_case(new_case(first_target_value="", first_target_type=None))
    state.open_case(case.id)
    yield window, state, case
    window.close()
    db.close()


def press(qtbot, window, key, modifier=Qt.KeyboardModifier.ControlModifier):
    qtbot.keyClick(window, key, modifier)


def add_findings(state, case, count: int) -> None:
    state.findings.add(case.id, [
        Finding(module="UserRecon", title=f"example_user on site{i}", source=f"site{i}.example.com",
                url=f"https://site{i}.example.com/example_user",
                result=ResultKind.UNCERTAIN if i % 5 == 0 else ResultKind.FOUND)
        for i in range(count)])


def test_shortcuts_navigate_and_focus(qtbot, ui):
    window, _state, _case = ui
    window.navigate("library")
    press(qtbot, window, Qt.Key.Key_K)
    lookup = window.screens["dashboard"].lookup.edit
    assert window.current_key() == "dashboard" and lookup.hasFocus()

    press(qtbot, window, Qt.Key.Key_N)
    assert window.current_key() == "newcase"
    press(qtbot, window, Qt.Key.Key_3)
    assert window.current_key() == "case"
    press(qtbot, window, Qt.Key.Key_F)
    workspace = window.screens["case"]
    assert workspace.tabs.current() == "findings" and workspace.findings_panel.search.edit.hasFocus()

    press(qtbot, window, Qt.Key.Key_6)
    assert window.current_key() == "library"
    press(qtbot, window, Qt.Key.Key_F)
    assert window.screens["library"].search.edit.hasFocus()
    press(qtbot, window, Qt.Key.Key_4)
    press(qtbot, window, Qt.Key.Key_F)
    assert window.current_key() == "modules" and window.screens["modules"].search.edit.hasFocus()

    assert "Ctrl+1" in window.sidebar.buttons["dashboard"].toolTip()
    assert "Ctrl+9" in window.sidebar.buttons["design"].toolTip()


def test_escape_closes_a_modal(qtbot, ui):
    window, _state, _case = ui
    notice = Notice(window, "Example notice", ["Fake text."])
    qtbot.addWidget(notice)
    notice.show()
    qtbot.keyClick(notice, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier)
    assert notice.result() == QDialog.DialogCode.Rejected and not notice.isVisible()


def test_empty_states_say_what_to_do(qtbot, ui):
    window, state, case = ui
    workspace = window.screens["case"]
    window.navigate("case")
    assert not workspace.findings_panel.empty.isHidden()
    workspace.tabs.set_current("targets")
    assert not workspace.targets_empty.isHidden() and workspace.targets_table.isHidden()

    add_findings(state, case, 3)
    state.case_updated(state.cases.get_case(case.id))
    panel = workspace.findings_panel
    workspace.tabs.set_current("findings")
    panel.search.edit.setText("no-such-word")
    assert not panel.no_match.isHidden() and panel.table.isHidden()
    panel.no_match.findChild(QPushButton, "ClearFindingFilters").click()
    assert panel.search.edit.text() == "" and panel.table.rowCount() == 3 and panel.no_match.isHidden()

    modules = window.screens["modules"]
    window.navigate("modules")
    modules.search.edit.setText("no-such-module")
    assert not modules.no_match.isHidden()
    modules.clear_filters()
    assert modules.no_match.isHidden() and modules.visible_ids()

    state.case_deleted()
    dashboard = window.screens["dashboard"]
    titles = [w.text() for w in dashboard.activity.findChildren(QLabel)]
    assert "No activity yet" in titles


def test_busy_state_while_checking_tools(qtbot, ui):
    window, _state, _case = ui
    settings = window.screens["settings"]
    settings.check_tools()
    assert not settings.check_btn.isEnabled() and settings.check_btn.text() == "Checking…"
    qtbot.waitUntil(settings.check_btn.isEnabled, timeout=10000)
    assert settings.check_btn.text() == "Check" and settings.tools_list.count() > 0


def test_unavailable_tools_say_how_to_fix_it(ui):
    window, state, _case = ui
    from app.screens.library import fix_hint
    from core.catalog import Availability

    sherlock = state.catalog.get("sherlock")
    hint = fix_hint(sherlock, Availability("Not installed", False, "old text"))
    assert "README › Optional tools" in hint and (sherlock.launch.venv or sherlock.launch.executable) in hint
    assert "Settings › API keys" in fix_hint(sherlock, Availability("Needs key", False, "old text"))


def test_big_case_findings_fill_fast(qtbot, ui):
    window, state, case = ui
    add_findings(state, case, 2000)
    panel = window.screens["case"].findings_panel
    start = time.perf_counter()
    panel.load(state.cases.get_case(case.id))
    elapsed = time.perf_counter() - start
    assert panel.table.rowCount() == 2000 and panel.more.isHidden()
    assert panel.table.cellWidget(0, 0) is None  # painted by the delegate, no widget per row
    assert elapsed < 1.5, f"2000 findings took {elapsed:.2f} s"  # ~0.2 s measured; was ~0.8 s for 300 rows


def test_long_console_stream_is_batched(qtbot, ui):
    window, _state, _case = ui
    console = window.screens["run"]
    start = time.perf_counter()
    for i in range(20000):
        console._line(f"[+] site{i}: https://site{i}.example.com/example_user", "g")
    console._flush()
    elapsed = time.perf_counter() - start
    assert console.console.document().blockCount() == 20000
    assert console.console.toPlainText().endswith("site19999: https://site19999.example.com/example_user")
    assert elapsed < 2.0, f"20000 lines took {elapsed:.2f} s"  # ~0.15 s measured; was ~5.6 s
