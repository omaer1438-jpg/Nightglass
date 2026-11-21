"""Arabic UI and right-to-left layout."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from PySide6.QtCore import Qt

from app import i18n
from app.main_window import MainWindow
from app.state import AppState
from core.db import Database


@pytest.fixture
def arabic(themed_app):
    i18n.set_language("ar")
    themed_app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    yield
    i18n.set_language("en")
    themed_app.setLayoutDirection(Qt.LayoutDirection.LeftToRight)


def test_tr_falls_back_to_english():
    assert i18n.tr("Dashboard") == "Dashboard"
    i18n.set_language("ar")
    try:
        assert i18n.tr("Dashboard") == "لوحة التحكم"
        assert i18n.tr("Some runtime text 42") == "Some runtime text 42"
        assert i18n.tr_status("Open") == "مفتوحة" and i18n.tr("Open") == "فتح"
    finally:
        i18n.set_language("en")


def test_arabic_window_is_right_to_left(qtbot, arabic, db_path, new_case):
    db = Database(db_path)
    state = AppState(db)
    window = MainWindow(state, str(db_path.parent))
    qtbot.addWidget(window)
    window.show()
    try:
        assert window.layoutDirection() == Qt.LayoutDirection.RightToLeft
        assert window.sidebar.buttons["dashboard"].text() == "لوحة التحكم"
        assert window.title_bar.crumb.text() == "/ لوحة التحكم"
        case = state.cases.create_case(new_case())
        state.open_case(case.id)
        assert window.screens["case"].close_btn.text() == "إغلاق القضية"
    finally:
        window.close()
        db.close()


def test_no_victim_wording_anywhere():
    """docs/PROJECT_RULES.md rule 8: UI and reports say target/subject, never victim (English or Arabic)."""
    root = Path(__file__).resolve().parent.parent
    for folder in ("app", "core", "adapters"):
        for path in (root / folder).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docstrings = {
                id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef)) and n.body
                and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                    text = node.value.lower()
                    assert "victim" not in text and "ضحية" not in text, path
