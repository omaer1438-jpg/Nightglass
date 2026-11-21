"""Tool library screen: catalog rows, filters, detail panel, reload."""

from __future__ import annotations

import shutil

import pytest
from PySide6.QtCore import Qt

from app.main_window import MainWindow
from app.screens.library import MAX_ROWS
from app.state import AppState
from core.catalog import TOOLS_DIR, load_catalog
from core.db import Database


@pytest.fixture
def tools_copy(tmp_path):
    target = tmp_path / "tools"
    shutil.copytree(TOOLS_DIR, target)
    return target


@pytest.fixture
def window(qtbot, themed_app, db_path, tools_copy):
    db = Database(db_path)
    win = MainWindow(AppState(db, tools_dir=tools_copy), str(db_path.parent))
    qtbot.addWidget(win)
    win.resize(1400, 900)
    win.show()
    win.navigate("library")
    yield win
    win.close()
    db.close()


def visible(screen) -> list[str]:
    return screen.visible_ids()


def test_lists_the_catalog(window):
    screen = window.screens["library"]
    total = len(load_catalog().tools)
    assert len(visible(screen)) == MAX_ROWS  # only the first page of a long catalog is built
    assert not screen.more.isHidden() and str(total) in screen.more.text()
    screen.search.edit.setText("sherlock")
    screen.apply_filters()
    assert "sherlock" in visible(screen) and screen.more.isHidden()
    assert screen.summary.text().startswith(f"{total} tools")
    assert window.sidebar.buttons["library"]._count == str(total)
    assert window.state.db.execute("SELECT COUNT(*) FROM tools").fetchone()[0] == total
    assert not screen.errors_banner.isVisible()


def test_filters_combine(qtbot, window):
    screen = window.screens["library"]
    qtbot.mouseClick(screen.category_chips["email"], Qt.MouseButton.LeftButton)
    assert {"epieos", "haveibeenpwned", "holehe", "hunter"} <= set(visible(screen))

    screen.behavior.buttons["active"].click()
    assert visible(screen) == ["holehe"]
    assert screen.rows["holehe"].status_label.text() == "Disabled"
    assert screen.detail.name.text() == "Holehe"
    assert screen.detail.settings_btn.isVisible()

    screen.behavior.buttons["local"].click()
    assert visible(screen) == []
    assert screen.no_match.isVisible()

    screen.clear_filters()
    qtbot.keyClicks(screen.search.edit, "exif")
    assert visible(screen) == ["exiftool"]

    screen.clear_filters()
    qtbot.mouseClick(screen.oss_chip, Qt.MouseButton.LeftButton)
    assert "haveibeenpwned" not in visible(screen)
    assert "sherlock" in visible(screen)


def test_selecting_a_row_shows_details(qtbot, window):
    screen = window.screens["library"]
    screen.search.edit.setText("exiftool")
    screen.apply_filters()
    qtbot.mouseClick(screen.rows["exiftool"].action, Qt.MouseButton.LeftButton)
    detail = screen.detail
    assert detail.name.text() == "ExifTool"
    assert "exiftool.org" in detail.link.text()
    assert "GPS" in detail.limitations.text.text()
    assert screen.rows["exiftool"].property("selected") is True


def test_enabling_an_active_tool_in_settings_updates_status(window):
    screen = window.screens["library"]
    window.state.db.set_setting("active.holehe", True)
    window.navigate("library")
    assert screen.rows["holehe"].status_label.text() != "Disabled"


def test_reload_reports_broken_manifest(qtbot, window, tools_copy):
    screen = window.screens["library"]
    (tools_copy / "broken.yaml").write_text("id: [", encoding="utf-8")
    (tools_copy / "tineye.yaml").unlink()
    screen.search.edit.setText("tineye")
    screen.apply_filters()
    assert "tineye" in screen.rows

    screen.reload()  # parses on a worker thread; the button shows the busy state meanwhile
    assert not screen.reload_btn.isEnabled() and screen.reload_btn.text() == "Reloading…"
    qtbot.waitUntil(screen.reload_btn.isEnabled, timeout=10000)

    assert screen.reload_btn.text() == "Reload catalog"
    assert "tineye" not in screen.rows
    assert screen.errors_banner.isVisible()
    assert "broken.yaml" in screen.errors_banner.text.text()
    assert "1 skipped" in window.status.message.text()


def test_findings_panel_caps_huge_cases(window):
    from app.screens.findings_panel import MAX_ROWS
    from core.cases import NewCase

    state = window.state
    case = state.cases.create_case(NewCase("Big case", "Hold many findings.", "Fake data only.", ["local"],
                                           "username", "example_user"))
    with state.db.transaction() as conn:
        conn.executemany("INSERT INTO findings (case_id,module,title,source,collected_at,status) VALUES (?,?,?,?,?,?)",
                         [(case.id, "UserRecon", f"Profile {i}", "Sherlock", "2026-10-29T19:41:00+00:00", "lead")
                          for i in range(MAX_ROWS + 5)])
    panel = window.screens["case"].findings_panel
    panel.load(case)
    assert panel.table.rowCount() == MAX_ROWS
    assert not panel.more.isHidden() and str(MAX_ROWS + 5) in panel.more.text()


def test_module_filters_combine_with_search(window):
    screen = window.screens["modules"]
    screen.target_filter["email"].click()
    assert {"emailfootprint", "emailprofile"} <= set(screen.visible_ids())
    assert "dnsrecon" not in screen.visible_ids()
    screen.mode_filter["active"].click()
    assert screen.visible_ids() == ["emailfootprint"]  # through its Holehe engine
    screen.mode_filter[""].click()
    screen.search.edit.setText("gravatar")
    assert screen.visible_ids() == ["emailprofile"]
    screen.search.edit.setText("zzz")
    assert screen.visible_ids() == [] and not screen.no_match.isHidden()


def test_modules_links_view_opens_browser_tools(window):
    screen = window.screens["modules"]
    screen.source_toggle.buttons["links"].click()
    ids = [t.id for t in screen.link_tools()]
    assert "ofw_disboard" in ids          # a browser link shows in the Links view
    assert "sherlock" not in ids          # runnable modules do not
    assert screen.mode_row.isHidden()  # the mode filter is hidden for links
    screen.target_filter["domain"].click()
    assert all("domain" in {x.value for x in t.target_types} for t in screen.link_tools())
    screen.target_filter[""].click()
    screen.source_toggle.buttons["modules"].click()
    assert not screen.mode_row.isHidden()
    assert "userrecon" in screen.visible_ids()  # modules are back
