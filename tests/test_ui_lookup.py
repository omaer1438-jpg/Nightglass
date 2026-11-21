"""Dashboard quick lookup: detect type -> add target -> modules filtered for it."""

from __future__ import annotations

import pytest
from PySide6.QtCore import Qt

from app.dialogs import Notice
from app.main_window import MainWindow
from app.state import AppState
from core.db import Database


@pytest.fixture
def ui(qtbot, themed_app, db_path):
    db = Database(db_path)
    state = AppState(db)
    window = MainWindow(state, str(db_path.parent))
    qtbot.addWidget(window)
    window.resize(1400, 900)
    window.show()
    yield window, state, qtbot
    window.close()
    db.close()


def test_analyze_needs_an_open_case(ui, monkeypatch):
    window, state, qtbot = ui
    shown = []
    monkeypatch.setattr(Notice, "exec", lambda self: shown.append(True) or 0)
    dash = window.screens["dashboard"]
    qtbot.keyClicks(dash.lookup.edit, "example.com")
    dash.analyze.click()
    assert shown and state.active_case is None


def test_analyze_adds_target_and_filters_modules(ui, new_case, monkeypatch):
    window, state, qtbot = ui
    case = state.cases.create_case(new_case(first_target_value=""))
    state.open_case(case.id, navigate=False)
    dash = window.screens["dashboard"]
    qtbot.keyClicks(dash.lookup.edit, "Example.COM")
    qtbot.keyClick(dash.lookup.edit, Qt.Key.Key_Return)

    [target] = state.cases.list_targets(case.id)
    assert (target.type.value, target.value, target.input_source) == ("domain", "example.com", "quick_lookup")
    assert window.current_key() == "modules"
    modules = window.screens["modules"]
    shown = modules.visible_ids()
    assert {"dnsrecon", "rdap", "subdomainscan", "sslchecker"} <= set(shown)
    assert "userrecon" not in shown and "phoneintel" not in shown

    launched = {}
    monkeypatch.setattr("app.screens.modules.launch_module",
                        lambda parent, st, spec, target=None: launched.update(spec=spec.id, target=target))
    modules.open_module("dnsrecon")
    assert launched == {"spec": "dnsrecon", "target": target}

    # Running it again doesn't duplicate the target; an invalid value is refused.
    window.navigate("dashboard")
    dash.analyze.click()
    assert len(state.cases.list_targets(case.id)) == 1
    monkeypatch.setattr(Notice, "exec", lambda self: 0)
    dash.lookup.edit.setText("not a target!!")
    dash.analyze.click()
    assert len(state.cases.list_targets(case.id)) == 1

    modules.set_preset(None)
    assert "userrecon" in modules.visible_ids()

