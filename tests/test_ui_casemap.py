"""UI: the Case Map board (spec section E). Fake data only."""

from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QPainter

from app.main_window import MainWindow
from app.screens import case_map_render
from app.screens.case_map_render import lod_for, render_png, render_svg, separate, thumbnail
from app.state import AppState
from core.cases import LookupMode, NewCase
from core.casemap import Board, MapFilter, add_link, add_note, build_graph, load_board
from core.db import Database
from core.findings import Confidence, Finding, FindingStatus, FindingStore
from core.reports import ReportOptions, redact, render


@pytest.fixture
def ui(qtbot, themed_app, db_path, new_case):
    db = Database(db_path)
    state = AppState(db, data_root=db_path.parent)
    window = MainWindow(state, str(db_path.parent))
    qtbot.addWidget(window)
    window.resize(1500, 1000)
    window.show()
    case = state.cases.create_case(new_case())
    target = state.cases.list_targets(case.id)[0]
    ids = state.findings.add(case.id, [
        Finding(module="UserRecon", title="GitHub profile", source="Sherlock",
                url="https://github.com/example_user", confidence=Confidence.HIGH),
        Finding(module="UserRecon", title="Keybase profile", source="Maigret",
                url="https://keybase.io/example_user", value="owner@example.com"),
    ], target_id=target.id)
    state.open_case(case.id)
    window.navigate("case")
    workspace = window.screens["case"]
    workspace.tabs.set_current("map")
    panel = workspace.map_panel
    qtbot.waitUntil(lambda: panel.scene is not None and f"f:{ids[0]}" in panel.scene.nodes, timeout=5000)
    qtbot.wait(50)  # let the deferred board-height fit and first fit-in-view settle
    yield window, state, case, ids, panel
    window.close()
    db.close()


def _rebuilt(qtbot, panel, predicate):
    qtbot.waitUntil(lambda: panel.scene is not None and not panel.dirty and predicate(), timeout=5000)


def test_lod_for_thresholds():
    assert [lod_for(z) for z in (0.1, 0.34, 0.35, 0.79, 0.8, 4.0)] == [
        "pin", "pin", "compact", "compact", "full", "full"]


def test_separate_pushes_overlapping_cards_apart():
    stacked = {"case": (0.0, 0.0), **{f"f:{i}": (i * 3.0, i * 2.0) for i in range(12)}}
    spread = separate(stacked, set(stacked) - {"case"})
    assert spread["case"] == (0.0, 0.0)  # fixed cards never move
    keys = list(spread)
    overlaps = sum(1 for i, a in enumerate(keys) for b in keys[i + 1:]
                   if abs(spread[a][0] - spread[b][0]) < 190 and abs(spread[a][1] - spread[b][1]) < 96)
    assert overlaps == 0


def test_empty_case_shows_empty_state_and_legend(qtbot, ui):
    window, state, _, _, panel = ui
    assert panel.legend_text.text() == "Connections are leads until verified."
    assert panel.board_stack.currentIndex() == 0
    empty = state.cases.create_case(NewCase(name="Own domain audit", purpose="Audit example.com",
                                            authorized_scope="example.com", allowed_modes=(LookupMode.LOCAL,)))
    state.open_case(empty.id)
    window.screens["case"].tabs.set_current("map")  # switching cases opens the Findings tab
    _rebuilt(qtbot, panel, lambda: panel.case.id == empty.id and list(panel.graph.nodes) == ["case"])
    assert panel.board_stack.currentIndex() == 1
    assert panel.empty.isVisible()


def test_live_refresh_after_case_updated(qtbot, ui):
    _, state, case, ids, panel = ui
    panel.select(f"f:{ids[0]}")
    center = panel.view.mapToScene(panel.view.viewport().rect().center())
    [new_id] = state.findings.add(case.id, [Finding(module="DNS", title="A record", source="dnspython",
                                                    value="192.0.2.10")])
    state.case_updated(state.cases.get_case(case.id))
    _rebuilt(qtbot, panel, lambda: f"f:{new_id}" in panel.scene.nodes)
    assert panel.selected == f"f:{ids[0]}"  # selection survives the rebuild
    assert (panel.view.mapToScene(panel.view.viewport().rect().center()) - center).manhattanLength() < 2
    assert f"f:{new_id}" in load_board(state.db, case.id).positions  # its new position was saved


def test_verify_from_the_map_persists(qtbot, ui):
    _, state, _, ids, panel = ui
    panel.select(f"f:{ids[0]}")
    assert panel.side.currentWidget() is panel.finding_detail
    panel.finding_detail.d_note.setPlainText("Matches my own account.")
    panel.finding_detail.btn_verify.click()
    assert state.findings.get(ids[0]).status is FindingStatus.VERIFIED
    _rebuilt(qtbot, panel, lambda: panel.graph.nodes[f"f:{ids[0]}"].status == "verified")
    assert panel.scene.nodes[f"f:{ids[0]}"].status_token == "green"


def test_add_note_card(qtbot, ui, monkeypatch):
    _, state, case, _, panel = ui
    monkeypatch.setattr("app.screens.case_map.QInputDialog.getMultiLineText",
                        lambda *a, **k: ("Same avatar on both profiles?", True))
    panel.add_note_btn.click()
    [note] = load_board(state.db, case.id).notes
    assert note.key in panel.scene.nodes and panel.scene.nodes[note.key].node.kind == "note"
    assert panel.side.currentWidget() is panel.note_card
    assert panel.note_edit.toPlainText() == "Same avatar on both profiles?"


def test_drag_from_pin_creates_analyst_string(qtbot, ui, monkeypatch):
    _, state, case, ids, panel = ui
    monkeypatch.setattr("app.screens.case_map.QInputDialog.getText", lambda *a, **k: ("same avatar", True))
    view = panel.view
    view.fit()
    a, b = panel.scene.nodes[f"f:{ids[0]}"], panel.scene.nodes[f"f:{ids[1]}"]
    start = view.mapFromScene(a.pin_pos())
    end = view.mapFromScene(b.pos())
    qtbot.mousePress(view.viewport(), Qt.MouseButton.LeftButton, pos=start)
    qtbot.mouseMove(view.viewport(), pos=end)
    qtbot.mouseRelease(view.viewport(), Qt.MouseButton.LeftButton, pos=end)
    [link] = load_board(state.db, case.id).links
    assert {link.a_key, link.b_key} == {a.key, b.key} and link.label == "same avatar"
    analyst = [e for e in panel.scene.edges if e.edge.kind == "analyst"]
    assert len(analyst) == 1 and analyst[0].tone == "lead"  # an analyst's string is always a lead


def test_pin_toggle_and_focus(qtbot, ui):
    _, state, case, ids, panel = ui
    key = f"f:{ids[0]}"
    panel.select(key)
    panel.view.setFocus()
    qtbot.keyClick(panel.view, Qt.Key.Key_P)
    assert key in load_board(state.db, case.id).pinned
    assert panel.scene.nodes[key].locked
    qtbot.keyClick(panel.view, Qt.Key.Key_P)
    assert key not in load_board(state.db, case.id).pinned

    panel.focus_chip.setChecked(True)  # 1 hop: the finding, its target and its source
    near = panel.scene.nodes["s:Sherlock"]
    far = panel.scene.nodes[f"f:{ids[1]}"]
    assert near.opacity() == pytest.approx(1.0)
    assert far.opacity() == pytest.approx(0.18)
    assert any(e.focus_dim for e in panel.scene.edges)
    panel.focus_chip.setChecked(False)
    assert far.opacity() == pytest.approx(1.0)


def test_filters_and_search(qtbot, ui):
    _, _, _, ids, panel = ui
    panel.kind_chips["finding"].setChecked(False)
    assert not panel.scene.nodes[f"f:{ids[0]}"].isVisible()
    assert not panel.scene.nodes["s:Sherlock"].isVisible()  # a source stays only while a finding shows
    panel.kind_chips["finding"].setChecked(True)
    panel.search.edit.setText("keybase")
    assert panel.scene.nodes[f"f:{ids[1]}"].matched and not panel.scene.nodes[f"f:{ids[0]}"].matched


def test_closed_case_is_read_only(qtbot, ui, monkeypatch):
    window, state, case, ids, panel = ui
    state.case_updated(state.cases.close_case(case.id))
    _rebuilt(qtbot, panel, lambda: not panel.case.is_open)
    assert not panel.add_note_btn.isEnabled() and not panel.view.linking_enabled
    assert panel.readonly_hint.isVisible()
    monkeypatch.setattr("app.screens.case_map.QInputDialog.getMultiLineText",
                        lambda *a, **k: pytest.fail("no notes on a closed case"))
    panel.add_note_here()
    panel.select(f"f:{ids[0]}")
    assert not panel.finding_detail.btn_verify.isEnabled()
    panel.toggle_pin(f"f:{ids[0]}")  # arranging the board is still allowed
    assert f"f:{ids[0]}" in load_board(state.db, case.id).pinned


def test_open_map_button_switches_tab(qtbot, ui):
    window, _, _, _, panel = ui
    workspace = window.screens["case"]
    workspace.tabs.set_current("findings")
    workspace.open_map.click()
    assert workspace.tabs.current() == "map"


def _png(path, color="#1d3b5a"):
    image = QImage(40, 30, QImage.Format.Format_RGB32)
    image.fill(QColor(color))
    image.save(str(path))
    return path


def test_thumbnails_only_for_images_inside_the_evidence_folder(themed_app, tmp_path):
    folder = tmp_path / "evidence"
    folder.mkdir()
    inside = _png(folder / "shot.png")
    outside = _png(tmp_path / "elsewhere.png")
    text = folder / "notes.txt"
    text.write_text("fake")
    case_map_render._thumbs.clear()
    pixmap = thumbnail(inside, folder)
    assert pixmap is not None and pixmap.width() <= 64 and pixmap.height() <= 48
    assert thumbnail(folder / "missing.png", folder) is None
    assert thumbnail(text, folder) is None
    assert thumbnail(outside, folder) is None


def test_exports_render_and_redact(themed_app, db, manager, new_case):
    case = manager.create_case(new_case())
    store_ids = FindingStore(db).add(case.id, [
        Finding(module="EmailCheck", title="Gravatar profile", source="Gravatar", value="owner@example.com")])
    add_note(db, case.id, 300, -200, "Write to owner@example.com later")
    board = load_board(db, case.id)
    graph = build_graph(db, case.id, board)
    assert f"f:{store_ids[0]}" in graph.nodes
    png = render_png(graph, board)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    svg = render_svg(graph, board).decode("utf-8")
    assert "<svg" in svg and "owner@example.com" in svg
    options = ReportOptions(redact_contacts=True)
    clean = render_svg(graph, board, redact=lambda s: redact(s, options)).decode("utf-8")
    assert "owner@example.com" not in clean and "[redacted email]" in clean
    only_notes = render_svg(graph, board, filt=MapFilter(kinds={"note"})).decode("utf-8")
    assert "Gravatar profile" not in only_notes


def test_report_html_and_markdown_include_the_map(qtbot, ui):
    window, state, case, ids, panel = ui
    note = add_note(state.db, case.id, 0, -400, "Ask owner@example.com about this")
    add_link(state.db, case.id, note.key, f"f:{ids[0]}", "same avatar")
    window.navigate("reports")
    screen = window.screens["reports"]
    assert screen.inc_map.isChecked() and screen.inc_map.text() == "Include case map and analyst notes"
    opts = screen.options()
    html = render(state.db, case.id, opts, screen.map_png(opts))
    assert "<h2>Case map</h2>" in html and "data:image/png;base64," in html
    assert "Analyst notes and links" in html and "same avatar" in html
    assert "owner@example.com" not in html and "[redacted email]" in html

    screen.fmt.set_current("md")
    screen._options_changed(new_path=True)
    saved = screen.export()
    sibling = saved.with_name(f"{saved.stem}-map.png")
    assert sibling.read_bytes()[:4] == b"\x89PNG"
    text = saved.read_text(encoding="utf-8")
    assert f"![Case map](<{sibling.name}>)" in text and "## Analyst notes and links" in text

    screen.inc_map.setChecked(False)
    assert "Case map" not in render(state.db, case.id, screen.options(), screen.map_png(screen.options()))
    screen.fmt.set_current("csv")
    assert "Case map" not in render(state.db, case.id, ReportOptions(fmt="csv"), b"png")


def test_export_board_uses_positions_on_screen(qtbot, ui):
    _, _, _, ids, panel = ui
    item = panel.scene.nodes[f"f:{ids[0]}"]
    item.setPos(1234, 567)
    board = panel.export_board()
    assert isinstance(board, Board) and board.positions[f"f:{ids[0]}"] == (1234, 567)


# ---- review fixes


def test_live_refresh_keeps_an_unsaved_verification_note(qtbot, ui):
    window, state, case, ids, panel = ui
    panel.select(f"f:{ids[0]}")
    qtbot.keyClicks(panel.finding_detail.d_note, "Checked by hand")
    state.findings.add(case.id, [Finding(module="DNS", title="A record", source="dnspython", value="192.0.2.10")])
    state.case_updated(state.cases.get_case(case.id))
    _rebuilt(qtbot, panel, lambda: len(panel.graph.nodes) > 5)
    assert panel.finding_detail.d_note.toPlainText() == "Checked by hand"
    panel.finding_detail.btn_verify.click()  # saving clears the "being typed" state
    assert state.findings.get(ids[0]).notes == "Checked by hand"
    assert not panel.finding_detail.d_note.document().isModified()

    findings = window.screens["case"].findings_panel  # the Findings tab shares the same detail card
    findings.select(ids[1])
    qtbot.keyClicks(findings.d_note, "Different person")
    state.case_updated(state.cases.get_case(case.id))
    assert findings.d_note.toPlainText() == "Different person"


def test_switching_case_saves_the_pending_note_first(qtbot, ui, monkeypatch):
    _, state, case, _, panel = ui
    monkeypatch.setattr("app.screens.case_map.QInputDialog.getMultiLineText", lambda *a, **k: ("First", True))
    panel.add_note_btn.click()
    [note] = load_board(state.db, case.id).notes
    panel.note_edit.setPlainText("First, then edited")  # autosave is still waiting on its 600 ms timer
    other = state.cases.create_case(NewCase(name="Own domain audit", purpose="Audit example.com",
                                            authorized_scope="example.com", allowed_modes=(LookupMode.LOCAL,)))
    state.open_case(other.id)
    assert load_board(state.db, case.id).notes[0].text == "First, then edited"
    assert panel.side.currentWidget() is panel.side_hint and panel._note_key is None


def test_stale_note_editor_is_replaced_on_refresh(qtbot, ui):
    _, _, _, _, panel = ui
    panel.side.setCurrentWidget(panel.note_card)
    panel._note_key = None
    panel.mark_dirty()
    _rebuilt(qtbot, panel, lambda: True)
    assert panel.side.currentWidget() is not panel.note_card


class _Deferred:
    """Stands in for run_in_background so a test decides when the worker 'finishes'."""

    def __init__(self):
        self.jobs = []

    def __call__(self, fn, done):
        self.jobs.append((fn, done))


def test_async_layout_keeps_cards_dragged_meanwhile(qtbot, ui, monkeypatch):
    _, state, case, ids, panel = ui
    deferred = _Deferred()
    monkeypatch.setattr("app.screens.case_map.ASYNC_LAYOUT", 0)
    monkeypatch.setattr("app.screens.case_map.run_in_background", deferred)
    [new_id] = state.findings.add(case.id, [Finding(module="DNS", title="A record", source="dnspython")])
    panel.mark_dirty()
    panel.rebuild()
    [(fn, done)] = deferred.jobs
    panel.scene.nodes[f"f:{ids[0]}"].setPos(900, 900)  # the user drags a card while the layout runs
    done(fn(), None)
    assert f"f:{new_id}" in panel.scene.nodes
    assert panel.scene.nodes[f"f:{ids[0]}"].pos().toTuple() == (900, 900)
    assert load_board(state.db, case.id).positions[f"f:{ids[0]}"] == (900, 900)


def test_failed_async_layout_leaves_the_map_dirty(qtbot, ui, monkeypatch):
    _, state, case, _, panel = ui
    deferred = _Deferred()
    monkeypatch.setattr("app.screens.case_map.ASYNC_LAYOUT", 0)
    monkeypatch.setattr("app.screens.case_map.run_in_background", deferred)
    state.findings.add(case.id, [Finding(module="DNS", title="A record", source="dnspython")])
    panel.mark_dirty()
    panel.rebuild()
    [(_, done)] = deferred.jobs
    done(None, RuntimeError("worker failed"))
    assert panel.dirty


def test_rebuild_during_a_string_drag_does_not_break_the_view(qtbot, ui, monkeypatch):
    _, state, case, ids, panel = ui
    monkeypatch.setattr("app.screens.case_map.QInputDialog.getText", lambda *a, **k: pytest.fail("gesture was reset"))
    view = panel.view
    view.fit()
    start = view.mapFromScene(panel.scene.nodes[f"f:{ids[0]}"].pin_pos())
    end = view.mapFromScene(panel.scene.nodes[f"f:{ids[1]}"].pos())
    qtbot.mousePress(view.viewport(), Qt.MouseButton.LeftButton, pos=start)
    panel.dirty = True
    panel.rebuild()  # e.g. a module run finished mid-gesture
    qtbot.mouseMove(view.viewport(), pos=end)
    qtbot.mouseRelease(view.viewport(), Qt.MouseButton.LeftButton, pos=end)
    qtbot.mouseMove(view.viewport(), pos=start)
    assert load_board(state.db, case.id).links == []


def test_note_autosave_updates_the_card_without_a_rebuild(qtbot, ui, monkeypatch):
    _, state, case, _, panel = ui
    monkeypatch.setattr("app.screens.case_map.QInputDialog.getMultiLineText", lambda *a, **k: ("Draft", True))
    panel.add_note_btn.click()
    [note] = load_board(state.db, case.id).notes
    builds = []
    monkeypatch.setattr("app.screens.case_map.build_graph", lambda *a, **k: builds.append(1))
    panel.note_edit.setPlainText("Avatar reused on two sites")
    qtbot.waitUntil(lambda: panel.note_status.text() == "Saved", timeout=3000)
    qtbot.wait(400)  # longer than the 250 ms refresh debounce
    assert builds == [] and not panel.dirty
    assert " ".join(panel.scene.nodes[note.key].title_lines) == "Avatar reused on two sites"
    assert panel.graph.nodes[note.key].label == "Avatar reused on two sites"
    assert load_board(state.db, case.id).notes[0].text == "Avatar reused on two sites"


def test_thumbnail_cache_is_bounded(themed_app, tmp_path, monkeypatch):
    folder = tmp_path / "evidence"
    folder.mkdir()
    monkeypatch.setattr(case_map_render, "MAX_THUMBS", 2)
    case_map_render._thumbs.clear()
    for index in range(5):
        thumbnail(_png(folder / f"shot{index}.png"), folder)
    assert len(case_map_render._thumbs) <= 2


def test_legend_never_calls_a_green_string_proof(qtbot, ui):
    _, _, _, _, panel = ui
    texts = [w.text() for w in panel.findChildren(type(panel.legend_text))]
    assert "Both findings verified — the link itself is still a lead" in texts
    assert "Verified" not in texts


def test_hidden_group_centre_keeps_visible_members_connected(qtbot, ui):
    _, state, case, ids, panel = ui
    a, b = state.findings.add(case.id, [
        Finding(module="EmailCheck", title="Gravatar profile", source="Gravatar", value="owner@example.com"),
        Finding(module="EmailCheck", title="Forum account", source="Maigret", value="owner@example.com")])
    state.findings.set_status(ids[1], FindingStatus.REJECTED, "Different person.")  # the group's centre card
    state.case_updated(state.cases.get_case(case.id))
    _rebuilt(qtbot, panel, lambda: f"f:{b}" in panel.scene.nodes)

    def linked(edges):
        return any({e.edge.src, e.edge.dst} == {f"f:{a}", f"f:{b}"} and e.isVisible() for e in edges)

    assert not linked(panel.scene.edges)  # drawn as a star around the centre card
    panel.hide_rejected.setChecked(True)
    assert linked(panel.scene.edges) and all(e.edge.kind == "shared" for e in panel._bridges)
    panel.hide_rejected.setChecked(False)
    assert panel._bridges == [] and not linked(panel.scene.edges)

    board = panel.export_board()
    scene, _ = case_map_render._export_scene(panel.graph, board, MapFilter(hide_rejected=True), None)
    assert f"f:{ids[1]}" not in scene.nodes and linked(scene.edges)
    assert render_png(panel.graph, board, filt=MapFilter(hide_rejected=True))[:4] == b"\x89PNG"
    assert "<svg" in render_svg(panel.graph, board, filt=MapFilter(hide_rejected=True)).decode("utf-8")


# ---- acceptance review fixes


@pytest.mark.parametrize("size", [(1480, 940), (1280, 800)])
def test_legend_and_empty_state_fit_the_default_window(qtbot, ui, size):
    window, state, _, _, panel = ui
    window.resize(*size)
    qtbot.wait(50)

    def on_screen(widget) -> bool:
        top = widget.mapTo(window, widget.rect().topLeft()).y()
        return widget.isVisible() and top + widget.height() <= window.height() - 24  # above the status bar

    assert on_screen(panel.legend_bar)
    empty = state.cases.create_case(NewCase(name="Own domain audit", purpose="Audit example.com",
                                            authorized_scope="example.com", allowed_modes=(LookupMode.LOCAL,)))
    state.open_case(empty.id)
    window.screens["case"].tabs.set_current("map")
    _rebuilt(qtbot, panel, lambda: panel.case.id == empty.id)
    qtbot.wait(50)
    assert on_screen(panel.empty.findChild(type(panel.add_note_btn), "EmptyAddNote"))


class _SpyPainter(QPainter):
    """Records each text drawn from Python with the layout direction in force at that moment."""

    def __init__(self, device):
        super().__init__(device)
        self.texts = []

    def drawText(self, *args):
        self.texts.append((args[-1], args[0], self.layoutDirection()))
        super().drawText(*args)


def _paint_card(node, direction=Qt.LayoutDirection.LeftToRight):
    from PySide6.QtWidgets import QStyleOptionGraphicsItem

    item = case_map_render.NodeItem(node, 1)
    image = QImage(300, 200, QImage.Format.Format_ARGB32_Premultiplied)
    painter = _SpyPainter(image)
    painter.translate(150, 100)
    painter.setLayoutDirection(direction)
    item.paint(painter, QStyleOptionGraphicsItem(), None)
    painter.end()
    return item, painter.texts


def test_value_line_sits_below_a_two_line_title(themed_app):
    from core.casemap import Node

    item, texts = _paint_card(Node("f:1", "finding", "A rather long finding title that needs two lines", 1,
                                   status="lead", module="UserRecon", value="https://example.com/example_user"))
    assert len(item.title_lines) == 2
    title_y = max(at.y() for text, at, _ in texts if text in item.title_lines)
    value_y = next(at.y() for text, at, _ in texts if text == item.value_text)
    assert value_y >= title_y + 10  # 11 px mono under a 12 px title line: no overlap


def test_card_values_stay_left_to_right_in_arabic(themed_app):
    from app import i18n
    from core.casemap import Node

    item, texts = _paint_card(Node("t:1", "target", "Phone target", 1, subtype="phone", value="+15550100"),
                              Qt.LayoutDirection.RightToLeft)
    [(_, _, direction)] = [t for t in texts if t[0] == item.value_text]
    assert direction == Qt.LayoutDirection.LeftToRight
    i18n.set_language("ar")
    try:
        for text in ("Map", "Open map", "Search the board", "Hide rejected", "Re-layout", "Fit", "Add note",
                     "Focus", "Connections are leads until verified.", "Sticky note", "Verify hash"):
            assert i18n.tr(text) != text
    finally:
        i18n.set_language("en")


def test_new_note_lands_on_a_free_spot(qtbot, ui, monkeypatch):
    _, state, case, _, panel = ui
    monkeypatch.setattr("app.screens.case_map.QInputDialog.getMultiLineText", lambda *a, **k: ("Check", True))
    panel.view.centerOn(panel.scene.nodes["case"].pos())  # right on top of the case card
    panel.add_note_btn.click()
    [note] = load_board(state.db, case.id).notes
    note_rect = panel.scene.nodes[note.key].sceneBoundingRect()
    assert not any(note_rect.intersects(item.sceneBoundingRect().adjusted(6, 12, -6, -6))
                   for key, item in panel.scene.nodes.items() if key != note.key)


def test_map_export_redacts_contacts_by_default(qtbot, ui, monkeypatch, tmp_path):
    _, _, _, _, panel = ui
    target = tmp_path / "map.svg"
    monkeypatch.setattr("app.screens.case_map.QFileDialog.getSaveFileName", lambda *a, **k: (str(target), ""))
    assert panel.redact_action.isChecked()
    panel.export_image("svg")
    text = target.read_text(encoding="utf-8")
    assert "owner@example.com" not in text and "[redacted email]" in text
    panel.redact_action.setChecked(False)
    panel.export_image("svg")
    assert "owner@example.com" in target.read_text(encoding="utf-8")
