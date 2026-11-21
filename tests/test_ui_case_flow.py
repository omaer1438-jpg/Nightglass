"""UI flow: New Case -> workspace -> save notes -> close -> reopen -> restart the app."""

from __future__ import annotations

import pytest
from PySide6.QtCore import Qt

from app import theme
from app.main_window import MainWindow
from app.state import AppState
from core.db import Database
from core.validation import TargetType


@pytest.fixture
def open_window(qtbot, themed_app, db_path):
    """Open the app on a database file; returns (window, db). Closes both at teardown."""
    opened: list[tuple[MainWindow, Database]] = []

    def factory():
        db = Database(db_path)
        window = MainWindow(AppState(db), str(db_path.parent))
        qtbot.addWidget(window)
        window.resize(1400, 900)
        window.show()
        opened.append((window, db))
        return window, db

    yield factory
    for window, db in opened:
        window.close()
        db.close()


def restart(window: MainWindow, db: Database):
    window.close()
    db.close()


def fill_new_case(qtbot, window: MainWindow, *, target_type="username", target="example_user"):
    window.navigate("newcase")
    screen = window.screens["newcase"]
    qtbot.keyClicks(screen.name, "Account impersonation review")
    qtbot.keyClicks(screen.purpose, "Check whether public profiles impersonate my own brand account.")
    qtbot.keyClicks(screen.scope, 'My own accounts and example.com. Profiles using "example_user".')
    qtbot.mouseClick(screen.type_buttons[target_type], Qt.MouseButton.LeftButton)
    qtbot.keyClicks(screen.target_value, target)
    return screen


def test_new_case_flow_creates_and_opens_case(qtbot, open_window):
    window, db = open_window()
    screen = fill_new_case(qtbot, window, target_type="email", target="Owner@Example.com")
    assert [s.property("step") for s in screen.steps] == ["done", "done", "done", "on"]

    qtbot.mouseClick(screen.create_btn, Qt.MouseButton.LeftButton)

    assert window.current_key() == "case"
    workspace = window.screens["case"]
    assert workspace.heading.text() == "Account impersonation review"
    assert "CASE-001" in window.title_bar.case_pill.text()
    assert window.status.case.text() == "CASE-001"
    [target] = window.state.cases.list_targets(1)
    assert (target.type.value, target.value) == ("email", "Owner@example.com")
    assert workspace.stat_targets.value.text() == "1"
    # The form is cleared for the next case.
    assert screen.name.text() == ""


def test_new_case_validation_blocks_saving(qtbot, open_window):
    window, db = open_window()
    window.navigate("newcase")
    screen = window.screens["newcase"]
    qtbot.mouseClick(screen.type_buttons["phone"], Qt.MouseButton.LeftButton)
    qtbot.keyClicks(screen.target_value, "555 010 0123")  # missing country code
    qtbot.mouseClick(screen.create_btn, Qt.MouseButton.LeftButton)

    assert window.current_key() == "newcase"
    assert db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0
    for field in (screen.f_name, screen.f_purpose, screen.f_scope, screen.f_target):
        assert field.error.isVisible()
    assert "E.164" in screen.f_target.error.text()
    # Typing clears that field's error immediately.
    qtbot.keyClicks(screen.name, "x")
    assert not screen.f_name.error.isVisible()


def test_save_close_reopen_survives_restart(qtbot, open_window):
    window, db = open_window()
    qtbot.mouseClick(fill_new_case(qtbot, window).create_btn, Qt.MouseButton.LeftButton)
    workspace = window.screens["case"]

    workspace.tabs.set_current("notes")
    qtbot.keyClicks(workspace.notes, "Bio links to example.com.")
    qtbot.mouseClick(workspace.save_notes_btn, Qt.MouseButton.LeftButton)
    assert window.state.cases.get_case(1).notes == "Bio links to example.com."

    qtbot.mouseClick(workspace.close_btn, Qt.MouseButton.LeftButton)
    assert window.state.cases.get_case(1).status == "closed"
    assert workspace.close_btn.text() == "Reopen case"
    assert workspace.notes.isReadOnly()
    assert not workspace.add_target_btn.isEnabled()
    assert workspace.closed_banner.isVisible()

    restart(window, db)
    window, db = open_window()

    # The last case is restored after a restart, still closed, data intact.
    workspace = window.screens["case"]
    assert workspace.case is not None and workspace.case.status == "closed"
    window.navigate("dashboard")
    dashboard = window.screens["dashboard"]
    assert dashboard.table.rowCount() == 1
    assert dashboard.table.cellWidget(0, 3).findChild(type(workspace.status_dot)).text() == "Closed"
    dashboard.table.cellClicked.emit(0, 1)
    assert window.current_key() == "case"

    qtbot.mouseClick(workspace.close_btn, Qt.MouseButton.LeftButton)
    case = window.state.cases.get_case(1)
    assert case.is_open and case.closed_at is None
    assert workspace.notes.toPlainText() == "Bio links to example.com."
    assert [t.value for t in window.state.cases.list_targets(1)] == ["example_user"]


def test_unsaved_notes_are_saved_on_exit(qtbot, open_window):
    window, db = open_window()
    qtbot.mouseClick(fill_new_case(qtbot, window).create_btn, Qt.MouseButton.LeftButton)
    workspace = window.screens["case"]
    workspace.tabs.set_current("notes")
    qtbot.keyClicks(workspace.notes, "draft that was never saved")

    restart(window, db)
    window, db = open_window()
    assert window.state.cases.get_case(1).notes == "draft that was never saved"


def test_add_target_validates_in_workspace(qtbot, open_window):
    window, db = open_window()
    qtbot.mouseClick(fill_new_case(qtbot, window).create_btn, Qt.MouseButton.LeftButton)
    workspace = window.screens["case"]
    workspace.tabs.set_current("targets")
    workspace.target_type.setCurrentIndex(list(TargetType).index(TargetType.IP))

    qtbot.keyClicks(workspace.target_input, "192.0.2.999")
    qtbot.mouseClick(workspace.add_target_btn, Qt.MouseButton.LeftButton)
    assert workspace.target_error.isVisible()
    assert window.state.cases.counts(1).targets == 1

    workspace.target_input.clear()
    qtbot.keyClicks(workspace.target_input, "192.0.2.10")
    qtbot.mouseClick(workspace.add_target_btn, Qt.MouseButton.LeftButton)
    assert not workspace.target_error.isVisible()
    assert workspace.targets_table.rowCount() == 2
    assert workspace.tabs._buttons["targets"]._count == "2"


def test_every_sidebar_item_opens_a_screen(qtbot, open_window):
    window, _ = open_window()
    for key, button in window.sidebar.buttons.items():
        qtbot.mouseClick(button, Qt.MouseButton.LeftButton)
        assert window.current_key() == key
        assert window.title_bar.crumb.text() == f"/ {window.screens[key].title}"


def test_theme_tokens_all_resolve(themed_app):
    text = theme.QSS_PATH.read_text(encoding="utf-8")
    sheet = theme.build_stylesheet(text, theme.tokens())
    assert "@" not in sheet
    assert theme.color("accent").name() == "#7ee787"
    with pytest.raises(KeyError):
        theme.build_stylesheet("QWidget { color: @nope; }", theme.tokens())
