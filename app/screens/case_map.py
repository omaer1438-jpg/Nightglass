"""Case Map tab: the case as an investigation board of pinned cards and strings.

Built only from what the case already holds (targets, findings, sources, evidence) plus the analyst's
own sticky notes and strings. Every string is a lead until a finding is verified.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import QEvent, QLineF, QPoint, QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QPainter, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGraphicsLineItem,
    QGraphicsView,
    QInputDialog,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QWidget,
)

from app import theme
from app.i18n import tr
from app.dialogs import Notice
from app.screens.case_map_render import (
    FOCUS_NODE_OPACITY,
    PEN_STYLE,
    EdgeItem,
    IMAGE_EXT,
    MapScene,
    NodeItem,
    render_png,
    render_svg,
    separate,
    thumbnail,
)
from app.screens.findings_panel import FindingDetail
from app.state import run_in_background
from app.widgets import Card, EmptyState, KeyValueGrid, SearchField, WrapText, button, chip_button, hbox, label, vbox
from core.cases import Case
from core.casemap import (
    MAX_LABEL,
    Board,
    MapFilter,
    add_link,
    add_note,
    apply_filter,
    bridge_edges,
    build_graph,
    delete_item,
    layout,
    load_board,
    neighborhood,
    save_positions,
    update_note,
)
from core.evidence import check_file
from core.reports import ReportOptions, redact
from core.runs import case_dir

ASYNC_LAYOUT = 150   # lay out bigger boards on a worker thread
MIN_BOARD_HEIGHT = 420  # legend + a 360 px board
PIN_HOT_ZONE = 14    # screen px around a card's pin that starts a string instead of a move
ZOOM_MIN, ZOOM_MAX, ZOOM_STEP = 0.1, 4.0, 1.15
KIND_CHIPS = [("target", "Targets"), ("finding", "Findings"), ("source", "Sources"), ("evidence", "Evidence"),
              ("note", "Notes")]
STATUS_CHIPS = [("lead", "Leads"), ("verified", "Verified"), ("uncertain", "Uncertain"), ("info", "Info"),
                ("rejected", "Rejected")]


class MapView(QGraphicsView):
    """Pan by dragging the board, zoom with the wheel under the mouse, drag a card's pin to connect it."""

    node_clicked = Signal(str)
    node_double_clicked = Signal(str)
    edge_clicked = Signal(object)        # EdgeItem
    background_clicked = Signal()
    link_requested = Signal(str, str)
    moved = Signal()
    key_action = Signal(str)             # "pin" | "delete"
    menu_requested = Signal(object, object, object)  # global QPoint, item or None, scene QPointF

    def __init__(self):
        super().__init__()
        self.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing
                            | QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.SmartViewportUpdate)
        self.setOptimizationFlag(QGraphicsView.OptimizationFlag.DontAdjustForAntialiasing)
        self.setFrameShape(QGraphicsView.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setMinimumHeight(360)  # with the case header above, the board still fits a 1280x800 window
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.linking_enabled = True
        self._link_from: NodeItem | None = None
        self._link_line: QGraphicsLineItem | None = None
        self._press = None
        self._press_item = None
        self._press_item_pos = None

    def zoom(self) -> float:
        return self.transform().m11()

    def zoom_by(self, factor: float) -> None:
        factor = max(ZOOM_MIN / self.zoom(), min(ZOOM_MAX / self.zoom(), factor))
        self.scale(factor, factor)

    def fit(self) -> None:
        scene = self.scene()
        if scene is None:
            return
        rect = scene.cards_rect().adjusted(-60, -60, 60, 60)
        self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
        if self.zoom() > 1.0:
            self.zoom_by(1.0 / self.zoom())
        elif self.zoom() < ZOOM_MIN:
            self.zoom_by(ZOOM_MIN / self.zoom())

    def reset_gesture(self) -> None:
        """Forget a press or string drag in progress (its items belong to a scene about to be replaced)."""
        if self._link_line is not None and self._link_line.scene() is not None:
            self._link_line.scene().removeItem(self._link_line)
        self._link_line = self._link_from = None
        self._press = self._press_item = self._press_item_pos = None

    def wheelEvent(self, event) -> None:
        steps = event.angleDelta().y() / 120
        if steps:
            self.zoom_by(ZOOM_STEP ** steps)
        event.accept()  # the wheel zooms the board; it never scrolls the page around it

    def keyPressEvent(self, event) -> None:
        key = event.key()
        if key == Qt.Key.Key_F:
            self.fit()
        elif key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
            self.zoom_by(ZOOM_STEP)
        elif key == Qt.Key.Key_Minus:
            self.zoom_by(1 / ZOOM_STEP)
        elif key == Qt.Key.Key_Escape:
            if self.scene():
                self.scene().clearSelection()
            self.background_clicked.emit()
        elif key == Qt.Key.Key_P:
            self.key_action.emit("pin")
        elif key == Qt.Key.Key_Delete:
            self.key_action.emit("delete")
        else:
            super().keyPressEvent(event)

    def _node_at(self, pos) -> NodeItem | None:
        for item in self.items(pos):
            if isinstance(item, NodeItem) and item.isVisible():
                return item
        return None

    def mousePressEvent(self, event) -> None:
        self._press = event.position().toPoint()
        node = self._node_at(self._press) if event.button() == Qt.MouseButton.LeftButton else None
        if node is not None and self.linking_enabled and node.pin_hit(self.mapToScene(self._press),
                                                                     PIN_HOT_ZONE / self.zoom()):
            self._link_from = node
            pen = QPen(theme.color("amber"), 1.4, Qt.PenStyle.DashLine)
            pen.setCosmetic(True)
            self._link_line = self.scene().addLine(QLineF(node.pin_pos(), node.pin_pos()), pen)
            self._link_line.setZValue(10)
            event.accept()
            return
        self._press_item = node
        self._press_item_pos = node.pos() if node is not None else None
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if self._link_line is not None:
            line = self._link_line.line()
            self._link_line.setLine(QLineF(line.p1(), self.mapToScene(event.position().toPoint())))
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        pos = event.position().toPoint()
        if self._link_line is not None:
            self.scene().removeItem(self._link_line)
            self._link_line = None
            source, self._link_from = self._link_from, None
            target = self._node_at(pos)
            if target is not None and target is not source:
                self.link_requested.emit(source.key, target.key)
            return
        super().mouseReleaseEvent(event)
        if event.button() != Qt.MouseButton.LeftButton or self._press is None:
            return
        node, start = self._press_item, self._press_item_pos
        if node is not None and start is not None and node.pos() != start:
            self.moved.emit()
        elif (pos - self._press).manhattanLength() < 4:
            item = self.itemAt(pos)
            if isinstance(item, NodeItem):
                self.node_clicked.emit(item.key)
            elif isinstance(item, EdgeItem):
                self.edge_clicked.emit(item)
            else:
                self.background_clicked.emit()
        self._press = self._press_item = self._press_item_pos = None

    def mouseDoubleClickEvent(self, event) -> None:
        node = self._node_at(event.position().toPoint())
        if node is not None:
            self.node_double_clicked.emit(node.key)
            return
        super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event) -> None:
        item = self.itemAt(event.pos())
        if not isinstance(item, (NodeItem, EdgeItem)):
            item = None
        self.menu_requested.emit(event.globalPos(), item, self.mapToScene(event.pos()))


class LegendSwatch(QWidget):
    """A short sample of a string (colour + line style), or a red card outline."""

    def __init__(self, token: str, style: str = "solid", width: float = 1.4, outline: bool = False):
        super().__init__()
        self._token, self._style, self._width, self._outline = token, style, width, outline
        self.setFixedSize(16 if outline else 26, 12)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        style = Qt.PenStyle.DashDotLine if self._style == "dashdot" else PEN_STYLE[self._style]
        painter.setPen(QPen(theme.color(self._token), self._width, style))
        if self._outline:
            painter.drawRoundedRect(QRectF(1.5, 1.5, 13, 9), 3, 3)
        else:
            painter.drawLine(QPointF(1, 6), QPointF(25, 6))


def _legend_item(swatch: LegendSwatch, text: str):
    return hbox(swatch, label(text, "hint"), spacing=5)


class CaseMapPanel(QWidget):
    def __init__(self, state):
        super().__init__()
        self.state = state
        self.case: Case | None = None
        self.graph = None
        self.board: Board | None = None
        self.scene: MapScene | None = None
        self.selected: str | None = None
        self.dirty = False
        self._gen = 0
        self._fitted_case: int | None = None
        self._note_key: str | None = None
        self._edge: EdgeItem | None = None
        self._bridges: list[EdgeItem] = []  # filter-only strings in the current scene
        self._watching = False
        self._timer = QTimer(self, singleShot=True, interval=250, timeout=self.rebuild)
        self._note_timer = QTimer(self, singleShot=True, interval=600, timeout=self._save_note)

        # ---- filter bar
        self.search = SearchField(tr("Search the board"))
        self.search.setFixedWidth(240)
        self.search.edit.textChanged.connect(self.apply_filters)
        self.kind_chips = {k: self._chip(t) for k, t in KIND_CHIPS}
        self.status_chips = {k: self._chip(t) for k, t in STATUS_CHIPS}
        self.module_box = QComboBox()
        self.module_box.setMinimumWidth(110)  # the filter rows fit a 1280 px window
        self.module_box.currentIndexChanged.connect(self.apply_filters)
        self.conf_box = QComboBox()
        for text, value in (("Any", ""), ("High", "high"), ("Medium", "medium"), ("Low", "low")):
            self.conf_box.addItem(tr(text), value)
        self.conf_box.currentIndexChanged.connect(self.apply_filters)
        self.hide_rejected = self._chip("Hide rejected", checked=False)
        self.focus_chip = self._chip("Focus", checked=False)
        self.focus_chip.setToolTip("Dim everything more than the chosen hops away from the selected card")
        self.hops = QComboBox()
        self.hops.addItem(tr("1 hop"), 1)
        self.hops.addItem(tr("2 hops"), 2)
        self.hops.currentIndexChanged.connect(self.apply_focus)
        self.focus_chip.toggled.connect(self.apply_focus)
        self.add_note_btn = button("Add note", icon="plus", on_click=lambda: self.add_note_here(), name="MapAddNote")
        self.relayout_btn = button("Re-layout", icon="rev", on_click=self.relayout, name="MapRelayout",
                                   tooltip="Arrange the board again. Pinned cards stay where they are.")
        self.fit_btn = button("Fit", on_click=lambda: self.view.fit(), tooltip="Fit the board in view (F)")
        self.export_btn = button("Export", icon="down", name="MapExport")
        export_menu = QMenu(self.export_btn)
        export_menu.addAction(tr("Export PNG…"), lambda: self.export_image("png"))
        export_menu.addAction(tr("Export SVG…"), lambda: self.export_image("svg"))
        export_menu.addSeparator()
        self.redact_action = export_menu.addAction(tr("Redact contacts and IPs"))  # same rules as reports
        self.redact_action.setCheckable(True)
        self.redact_action.setChecked(True)
        self.export_btn.setMenu(export_menu)
        row1 = hbox(self.search, *self.kind_chips.values(), None, *self.status_chips.values(), spacing=6)
        row2 = hbox(label("Module", "meta"), self.module_box, label("Confidence", "meta"), self.conf_box,
                    self.hide_rejected, self.focus_chip, self.hops, None, self.add_note_btn, self.relayout_btn,
                    self.fit_btn, self.export_btn, spacing=8)
        self.readonly_hint = label("This case is closed: notes and strings are read-only. You can still arrange "
                                   "and pin cards.", "hint", wrap=True)

        # ---- board
        self.view = MapView()
        self.view.node_clicked.connect(self.select)
        self.view.node_double_clicked.connect(self._double_clicked)
        self.view.edge_clicked.connect(self._edge_clicked)
        self.view.background_clicked.connect(lambda: self.select(None))
        self.view.link_requested.connect(self.connect_cards)
        self.view.moved.connect(self.save_board_positions)
        self.view.key_action.connect(self._key_action)
        self.view.menu_requested.connect(self._menu)
        self.legend_text = label("Connections are leads until verified.", "muted")
        self.legend_text.setStyleSheet("font-size: 12px;")
        self.omitted = label("", "hint")
        self.busy = label("", "hint")
        legend = vbox(  # three short rows: the board column stays narrow enough for a 1280 px window
            hbox(self.legend_text, 10, _legend_item(LegendSwatch("amber"), "Lead"),
                 _legend_item(LegendSwatch("dim"), "Rejected"), None, self.busy, self.omitted, spacing=10),
            hbox(_legend_item(LegendSwatch("green"), "Both findings verified — the link itself is still a lead"),
                 None, spacing=10),
            hbox(_legend_item(LegendSwatch("muted"), "High"), _legend_item(LegendSwatch("muted", "dash"), "Medium"),
                 _legend_item(LegendSwatch("muted", "dot"), "Low confidence"),
                 _legend_item(LegendSwatch("amber", "dashdot", 0.8), "Analyst string"), 10,
                 _legend_item(LegendSwatch("red", width=1.5, outline=True), "red outline = active module"),
                 None, spacing=10),
            spacing=4, margins=(14, 8, 14, 8))
        legend_bar = QWidget()
        legend_bar.setObjectName("MapLegend")
        legend_bar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        # Above the board, so "leads until verified" is always on screen however tall the page gets.
        legend_bar.setStyleSheet(f"#MapLegend {{ border-top: none; border-bottom: 1px solid {theme.tokens()['border']}; }}")
        legend_bar.setLayout(legend)
        self.legend_bar = legend_bar
        board = Card(padding=(0, 0, 0, 0))
        board.body_layout.setSpacing(0)
        board.body_layout.addWidget(legend_bar)
        board.body_layout.addWidget(self.view, 1)

        self.empty = EmptyState(
            "tree", "Nothing to map yet",
            "Add a target and run a module to see findings, sources and evidence as cards here, "
            "or add a sticky note to start a board.",
            [button("Open modules", icon="mod", on_click=lambda: state.navigate("modules")),
             button("Add note", icon="plus", on_click=lambda: self.add_note_here(), name="EmptyAddNote")])
        empty_card = Card()
        empty_card.body_layout.addStretch(1)  # centred in the board area, actions included
        empty_card.body_layout.addWidget(self.empty)
        empty_card.body_layout.addStretch(1)
        self.board_stack = QStackedWidget()
        self.board_stack.addWidget(board)
        self.board_stack.addWidget(empty_card)

        # ---- side panel
        self.side = QStackedWidget()
        self.side.setFixedWidth(340)
        self.side_hint = Card("Board")
        self.side_hint.body_layout.addWidget(label(
            "Click a card to see its detail. Drag a card to move it; drag from its pin to another card to "
            "connect them. Right-click for more.", "muted", wrap=True))
        self.side_hint.body_layout.addWidget(label("F fit · +/− zoom · P pin · Esc clear", "hint", mono=True))
        self.side_hint.body_layout.addStretch(1)
        self.finding_detail = FindingDetail(state)
        self.finding_detail.changed.connect(self._finding_changed)
        self.note_card, self.note_edit, self.note_status, self.note_delete = self._note_page()
        self.link_card, self.link_text, self.link_delete = self._link_page()
        self.info_card = Card("Card")
        self.info_title = label("", "h2", wrap=True, selectable=True)
        self.info_value = WrapText(mono=True)
        self.info_facts = KeyValueGrid()
        self.verify_btn = button("Verify hash", icon="shield", on_click=self._verify_hash, name="MapVerifyHash")
        self.verify_result = label("", "hint", wrap=True)
        for widget in (self.info_title, self.info_value, self.info_facts, self.verify_btn, self.verify_result):
            self.info_card.body_layout.addWidget(widget)
        self.info_card.body_layout.addStretch(1)
        for page in (self.side_hint, self.finding_detail, self.note_card, self.link_card, self.info_card):
            self.side.addWidget(page)

        body = hbox(spacing=14)
        body.addWidget(self.board_stack, 1, Qt.AlignmentFlag.AlignTop)  # fixed height: see _fit_height
        body.addWidget(self.side, 0, Qt.AlignmentFlag.AlignTop)
        self.setLayout(vbox(row1, row2, self.readonly_hint, body, None, spacing=10))

    # ---- widgets

    def _chip(self, text: str, checked: bool = True) -> QPushButton:
        chip = chip_button(text)
        chip.setChecked(checked)
        chip.toggled.connect(self.apply_filters)
        return chip

    def _note_page(self):
        card = Card("Sticky note")
        edit = QPlainTextEdit()
        edit.setObjectName("MapNoteEdit")
        edit.setPlaceholderText("What do you think connects here? Notes stay on this computer.")
        edit.setMinimumHeight(180)
        edit.textChanged.connect(lambda: self._note_timer.start() if not edit.isReadOnly() else None)
        status = label("", "hint")
        delete = button("Delete note", "danger", on_click=self.delete_selected, name="MapDeleteNote")
        card.body_layout.addWidget(edit)
        card.body_layout.addLayout(hbox(status, None, delete))
        return card, edit, status, delete

    def _link_page(self):
        card = Card("Analyst connection")
        text = label("", wrap=True, selectable=True)
        hint = label("Your own string. It stays a lead: it records what you suspect, not a verified fact.",
                     "hint", wrap=True)
        delete = button("Delete connection", "danger", on_click=self.delete_selected, name="MapDeleteLink")
        for widget in (text, hint):
            card.body_layout.addWidget(widget)
        card.body_layout.addLayout(hbox(None, delete))
        return card, text, delete

    # ---- data

    @property
    def editable(self) -> bool:
        return bool(self.case and self.case.is_open)

    def set_case(self, case: Case | None) -> None:
        if case is None or self.case is None or case.id != self.case.id:
            self._flush_note()  # save a pending note edit to the case it belongs to, before switching
            self.selected = None
            self._note_key = None
            self.side.setCurrentWidget(self.side_hint)
        self.case = case
        self.mark_dirty()

    def mark_dirty(self) -> None:
        self.dirty = True
        if self.isVisible():
            self._timer.start()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        area = self._scroll_area()
        if area is not None and not self._watching:
            area.viewport().installEventFilter(self)  # refit the board when the window is resized
            self._watching = True
        QTimer.singleShot(0, self._fit_height)
        if self.dirty:
            self._timer.start(0)

    def _scroll_area(self) -> QScrollArea | None:
        area = self.parentWidget()
        while area is not None and not isinstance(area, QScrollArea):
            area = area.parentWidget()
        return area

    def eventFilter(self, obj, event) -> bool:
        if event.type() == QEvent.Type.Resize and self.isVisible():
            self._fit_height()
        return False

    def _fit_height(self) -> None:
        """The board fills what is left of the window below the case header (the workspace page itself
        is as tall as its tallest tab), so the legend and the empty state's actions stay on screen."""
        area = self._scroll_area()
        if area is None or area.widget() is None:
            return
        top = self.board_stack.mapTo(area.widget(), QPoint(0, 0)).y()
        self.board_stack.setFixedHeight(max(MIN_BOARD_HEIGHT, area.viewport().height() - top - 12))

    def rebuild(self) -> None:
        """Rebuild from the database; keeps viewport, selection and saved positions."""
        self._timer.setInterval(250)
        if self.case is None or not self.dirty:
            return
        self.dirty = False
        case_id = self.case.id
        board = load_board(self.state.db, case_id)
        graph = build_graph(self.state.db, case_id, board)
        self._gen += 1
        gen = self._gen
        missing = [k for k in graph.nodes if k not in board.positions]
        if not missing:
            self._apply(gen, case_id, graph, board, dict(board.positions), False)
            return
        work = lambda: separate(layout(graph, saved=board.positions, pinned=frozenset(board.pinned)), set(missing))  # noqa: E731
        if len(graph.nodes) <= ASYNC_LAYOUT:
            self._apply(gen, case_id, graph, board, work(), True)
            return
        self.busy.setText(f"Arranging {len(graph.nodes)} cards…")
        run_in_background(work, lambda result, error: self._layout_done(gen, case_id, graph, board, result, error))

    def _layout_done(self, gen, case_id, graph, board, result, error) -> None:
        self.busy.setText("")
        if error is not None:
            self.dirty = True  # try again on the next refresh or show instead of staying stale
            self.state.say(f"The case map couldn't be arranged: {error}")
            return
        if self.scene is not None and self.case is not None and self.case.id == case_id:
            # Cards the user dragged while the layout ran keep where they were put.
            result = {**result, **{k: (item.x(), item.y()) for k, item in self.scene.nodes.items() if k in result}}
        self._apply(gen, case_id, graph, board, result, True)

    def _apply(self, gen: int, case_id: int, graph, board: Board, positions: dict, save: bool) -> None:
        if gen != self._gen or self.case is None or self.case.id != case_id:
            return  # a newer rebuild or another case took over
        if save:
            save_positions(self.state.db, case_id, positions, board.pinned, keep=set(graph.nodes))
        old_scene, old_center = self.scene, self.view.mapToScene(self.view.viewport().rect().center())
        scroll = (self.view.horizontalScrollBar().value(), self.view.verticalScrollBar().value())
        self.graph, self.board = graph, board
        self.scene = MapScene(graph, positions, thumb=self._thumb)
        self._bridges = []
        rect = self.scene.cards_rect()
        # Same scene rect as before when the cards still fit in it: then the scroll position carries over exactly.
        same_rect = old_scene is not None and old_scene.sceneRect().contains(rect.adjusted(-500, -500, 500, 500))
        self.scene.setSceneRect(old_scene.sceneRect() if same_rect else rect.adjusted(-4000, -4000, 4000, 4000))
        for key in board.pinned:
            if key in self.scene.nodes:
                self.scene.nodes[key].set_locked(True)
        self.view.reset_gesture()  # a drag or string in progress points at items of the old scene
        self.view.setScene(self.scene)
        if old_scene is not None:
            old_scene.deleteLater()
        empty = len(graph.nodes) <= 1
        self.board_stack.setCurrentIndex(1 if empty else 0)
        if self._fitted_case != case_id:
            self._fitted_case = case_id
            QTimer.singleShot(0, self.view.fit)  # after the view has its real size
        elif same_rect:
            self.view.horizontalScrollBar().setValue(scroll[0])
            self.view.verticalScrollBar().setValue(scroll[1])
        else:
            self.view.centerOn(old_center)
        collapsed, omitted = graph.stats.get("collapsed", 0), graph.stats.get("omitted_buckets", 0)
        self.omitted.setText(" · ".join(filter(None, [
            f"{collapsed} dense groups collapsed" if collapsed else "",
            f"{omitted} more not drawn" if omitted else ""])))
        self._fill_modules()
        self._apply_editable()
        if self.selected not in graph.nodes:
            self.selected = None
        self.apply_filters()
        self.select(self.selected, refresh_side=self.side.currentWidget() is not self.note_card or self._note_key is None)

    def _fill_modules(self) -> None:
        current = self.module_box.currentData()
        modules = sorted({n.module for n in self.graph.nodes.values() if n.kind == "finding" and n.module})
        self.module_box.blockSignals(True)
        self.module_box.clear()
        self.module_box.addItem("Any", "")
        for name in modules:
            self.module_box.addItem(name, name)
        self.module_box.setCurrentIndex(max(self.module_box.findData(current), 0) if current else 0)
        self.module_box.blockSignals(False)

    def _apply_editable(self) -> None:
        editable = self.editable
        self.view.linking_enabled = editable
        for widget in (self.add_note_btn, self.note_delete, self.link_delete):
            widget.setEnabled(editable)
        self.empty.findChild(QPushButton, "EmptyAddNote").setEnabled(editable)
        self.note_edit.setReadOnly(not editable)
        self.readonly_hint.setVisible(not editable)
        QTimer.singleShot(0, self._fit_height)  # the hint moves the board down

    def _thumb(self, node):
        if node.kind != "evidence" or node.ref_id is None or Path(node.detail).suffix.lower() not in IMAGE_EXT:
            return None
        try:
            record = self.state.evidence.get(node.ref_id)
        except KeyError:
            return None
        return thumbnail(record.path, case_dir(record.case_id, self.state.evidence.root) / "evidence")

    # ---- filters and focus

    def current_filter(self) -> MapFilter:
        kinds = {k for k, chip in self.kind_chips.items() if chip.isChecked()}
        statuses = {k for k, chip in self.status_chips.items() if chip.isChecked()}
        module, conf = self.module_box.currentData(), self.conf_box.currentData()
        return MapFilter(kinds=None if len(kinds) == len(KIND_CHIPS) else kinds,
                         statuses=None if len(statuses) == len(STATUS_CHIPS) else statuses,
                         modules={module} if module else None, confidences={conf} if conf else None,
                         hide_rejected=self.hide_rejected.isChecked(), query=self.search.edit.text())

    def apply_filters(self) -> None:
        if self.scene is None:
            return
        visible, matched = apply_filter(self.graph, self.current_filter())
        # Stand-in strings for shared groups whose centre card this filter hides; replaced on every change.
        self.scene.remove_edges(self._bridges)
        self._bridges = self.scene.add_edges(bridge_edges(self.graph, visible), self.graph.nodes)
        for key, item in self.scene.nodes.items():
            item.setVisible(key in visible)
            if item.matched != (key in matched):
                item.matched = key in matched
                item.update()
        for edge in self.scene.edges:
            edge.setVisible(edge.a.key in visible and edge.b.key in visible)
        self.apply_focus()

    def apply_focus(self) -> None:
        if self.scene is None:
            return
        hood = None
        if self.focus_chip.isChecked() and self.selected in self.graph.nodes:
            hood = neighborhood(self.graph, self.selected, self.hops.currentData())
        for key, item in self.scene.nodes.items():
            item.setOpacity(item.base_opacity * (1 if hood is None or key in hood else FOCUS_NODE_OPACITY))
        for edge in self.scene.edges:
            edge.focus_dim = hood is not None and not (edge.a.key in hood and edge.b.key in hood)
        self.scene.layer.invalidate()

    # ---- selection and side panel

    def select(self, key: str | None, refresh_side: bool = True) -> None:
        self._flush_note()
        self.selected = key
        self._edge = None
        if self.scene is not None:
            self.scene.clearSelection()
            item = self.scene.nodes.get(key) if key else None
            if item is not None:
                item.setSelected(True)
        self.apply_focus()
        if refresh_side:
            self._show_side(key)

    def _show_side(self, key: str | None) -> None:
        node = self.graph.nodes.get(key) if self.graph is not None and key else None
        if node is None:
            self.side.setCurrentWidget(self.side_hint)
        elif node.kind == "finding":
            self.finding_detail.show_finding(node.ref_id, self.editable)
            self.side.setCurrentWidget(self.finding_detail)
        elif node.kind == "note":
            self._note_key = key
            self.note_edit.blockSignals(True)
            self.note_edit.setPlainText(node.value)
            self.note_edit.blockSignals(False)
            self.note_status.setText("" if self.editable else tr("Read-only while the case is closed"))
            self.side.setCurrentWidget(self.note_card)
        else:
            self._show_info(node)

    def _show_info(self, node) -> None:
        titles = {"case": "Case", "target": "Target", "source": "Source", "evidence": "Evidence file",
                  "value": "Shared value"}
        self.info_card.title_label.setText(tr(titles.get(node.kind, "Card")))
        self.info_title.setText(node.label)
        self.info_value.setPlainText(node.value if node.value != node.label else "")
        self.info_value.setVisible(bool(node.value) and node.value != node.label)
        rows = [("Connected", str(len(self.graph.adj.get(node.key, ()))))]
        if node.kind == "target":
            rows.insert(0, ("Type", node.subtype))
        elif node.kind == "evidence":
            rows.insert(0, ("File", node.detail))
            rows.insert(1, ("SHA-256", label(node.value, mono=True, wrap=True, selectable=True)))
            self.info_value.setVisible(False)
        elif node.kind == "value":
            rows.insert(0, ("Kind", f"same {node.subtype}"))
            rows.append(("Meaning", "A shared value is a lead, not proof that the cards belong together."))
        self.info_facts.set_rows(rows)
        self.verify_btn.setVisible(node.kind == "evidence")
        self.verify_btn.setEnabled(True)
        self.verify_result.setText("")
        self.side.setCurrentWidget(self.info_card)

    def _edge_clicked(self, edge: EdgeItem) -> None:
        if edge.edge.kind != "analyst":
            self.select(None)
            return
        self.select(None, refresh_side=False)
        self._edge = edge
        a, b = edge.a.node.label, edge.b.node.label
        text = edge.edge.label.removeprefix("analyst").lstrip(": ")
        self.link_text.setText(f"“{a}” ↔ “{b}”" + (f"\n{text}" if text else ""))
        self.side.setCurrentWidget(self.link_card)

    def _double_clicked(self, key: str) -> None:
        self.select(key)
        if key.startswith("n:") and self.editable:
            self.note_edit.setFocus()

    def _finding_changed(self) -> None:
        self.state.case_updated(self.state.cases.get_case(self.case.id))

    def _verify_hash(self) -> None:
        node = self.graph.nodes.get(self.selected) if self.selected else None
        if node is None or node.kind != "evidence":
            return
        record = self.state.evidence.get(node.ref_id)
        self.verify_btn.setEnabled(False)
        self.verify_result.setText("Checking…")
        key = node.key

        def done(ok, error) -> None:
            self.verify_btn.setEnabled(True)
            if self.selected != key:
                return
            if error is not None:
                self.verify_result.setText(f"The hash check failed: {error}")
            else:
                self.verify_result.setText({True: "Matches the recorded SHA-256.",
                                            False: "CHANGED: the file no longer matches its recorded SHA-256.",
                                            None: "Missing: the file is no longer in the evidence folder."}[ok])

        run_in_background(lambda: check_file(record.path, record.sha256), done)

    # ---- board edits

    def _positions(self) -> dict:
        return {k: (item.x(), item.y()) for k, item in self.scene.nodes.items()} if self.scene else {}

    def save_board_positions(self) -> None:
        if self.case is None or self.scene is None:
            return
        save_positions(self.state.db, self.case.id, self._positions(), self.board.pinned)
        self.board.positions.update(self._positions())

    def toggle_pin(self, key: str | None = None) -> None:
        key = key or self.selected
        if self.scene is None or key not in self.scene.nodes:
            return
        pinned = key not in self.board.pinned
        (self.board.pinned.add if pinned else self.board.pinned.discard)(key)
        self.scene.nodes[key].set_locked(pinned)
        self.save_board_positions()

    def unpin_all(self) -> None:
        if self.scene is None:
            return
        for key in list(self.board.pinned):
            if key in self.scene.nodes:
                self.scene.nodes[key].set_locked(False)
        self.board.pinned.clear()
        self.save_board_positions()

    def relayout(self) -> None:
        if self.scene is None:
            return
        current = self._positions()
        saved = {k: current[k] for k in self.board.pinned if k in current}
        graph, gen, case_id = self.graph, self._gen, self.case.id
        work = lambda: separate(layout(graph, saved=saved, pinned=frozenset(saved)), set(graph.nodes) - set(saved))  # noqa: E731

        def done(result, error) -> None:
            self.busy.setText("")
            if error is not None or gen != self._gen or self.case is None or self.case.id != case_id:
                return
            for key, (x, y) in result.items():
                if key in self.scene.nodes:
                    self.scene.nodes[key].setPos(x, y)
            self.save_board_positions()
            self.view.fit()

        if len(graph.nodes) <= ASYNC_LAYOUT:
            done(work(), None)
        else:
            self.busy.setText(f"Arranging {len(graph.nodes)} cards…")
            run_in_background(work, done)

    def add_note_here(self, at: QPointF | None = None) -> None:
        if not self.editable:
            return
        text, ok = QInputDialog.getMultiLineText(self, tr("Add note"), tr("Note"))
        if not ok or not text.strip():
            return
        if at is None:
            at = self.view.mapToScene(self.view.viewport().rect().center())
        # Drop it on a free spot near there, not on top of the case card or another card.
        if self._positions():
            at = QPointF(*separate({**self._positions(), "n:new": (at.x(), at.y())}, {"n:new"})["n:new"])
        try:
            note = add_note(self.state.db, self.case.id, at.x(), at.y(), text)
        except ValueError as exc:
            self.state.say(str(exc))
            return
        self.selected = note.key
        self.dirty = True
        self.rebuild()
        self.state.say("Note added to the board.")

    def connect_cards(self, a: str, b: str) -> None:
        if not self.editable:
            return
        text, ok = QInputDialog.getText(self, "Connect cards", "Label (optional), e.g. same writing style")
        if not ok:
            return
        try:
            add_link(self.state.db, self.case.id, a, b, text, valid_keys=set(self.graph.nodes))
        except ValueError as exc:
            self.state.say(str(exc))
            return
        self.dirty = True
        self.rebuild()
        self.state.say("Connection added. It stays a lead until you verify the findings.")

    def delete_selected(self) -> None:
        if not self.editable:
            return
        if self._edge is not None and self._edge.edge.kind == "analyst":
            ends = {self._edge.edge.src, self._edge.edge.dst}
            link = next((l for l in self.board.links if {l.a_key, l.b_key} == ends), None)
            if link is None or not self._confirm("Delete this connection?", "Delete connection"):
                return
            kind, key = "link", link.key
        elif self.selected and self.selected.startswith("n:"):
            if not self._confirm("Delete this note?", "Delete note"):
                return
            kind, key = "note", self.selected
            self._note_timer.stop()
            self._note_key = None
        else:
            return
        try:
            delete_item(self.state.db, self.case.id, kind, key)
        except ValueError as exc:
            self.state.say(str(exc))
            return
        self.select(None)
        self.dirty = True
        self.rebuild()

    def _confirm(self, title: str, action: str) -> bool:
        dialog = Notice(self.window(), title, ["It is removed from this board. Findings are not changed."],
                        tone="red", action=(action, None))
        dialog.exec()
        return dialog.action_taken

    def _save_note(self) -> None:
        key = self._note_key
        if key is None or self.case is None or not self.editable:
            return
        try:
            update_note(self.state.db, self.case.id, key, text=self.note_edit.toPlainText())
        except (ValueError, KeyError) as exc:
            self.note_status.setText(str(exc))
            return
        self.note_status.setText(tr("Saved"))
        # Update just this card (same label rule as core build_graph) instead of rebuilding the whole board.
        node = self.graph.nodes.get(key) if self.graph is not None else None
        item = self.scene.nodes.get(key) if self.scene is not None else None
        if node is not None and item is not None:
            text = self.note_edit.toPlainText().strip()
            node = replace(node, label=text.split("\n", 1)[0][:MAX_LABEL] or "Note", value=text)
            self.graph.nodes[key] = node
            item.set_note(node)

    def _flush_note(self) -> None:
        if self._note_timer.isActive():
            self._note_timer.stop()
            self._save_note()

    def _key_action(self, action: str) -> None:
        if action == "pin":
            self.toggle_pin()
        elif action == "delete":
            self.delete_selected()

    def _menu(self, global_pos, item, scene_pos) -> None:
        menu = QMenu(self)
        if isinstance(item, NodeItem):
            self.select(item.key)
            menu.addAction(tr("Unpin" if item.locked else "Pin in place"), lambda: self.toggle_pin(item.key))
            menu.addAction(tr("Focus here"), lambda: self.focus_chip.setChecked(True))
            if item.key.startswith("n:") and self.editable:
                menu.addAction(tr("Edit note"), lambda: self.note_edit.setFocus())
                menu.addAction(tr("Delete note"), self.delete_selected)
        elif isinstance(item, EdgeItem) and item.edge.kind == "analyst":
            self._edge_clicked(item)
            if self.editable:
                menu.addAction(tr("Delete connection"), self.delete_selected)
        else:
            if self.editable:
                menu.addAction(tr("Add note here"), lambda: self.add_note_here(scene_pos))
            menu.addAction(tr("Fit board"), self.view.fit)
            menu.addAction(tr("Re-layout"), self.relayout)
            menu.addAction(tr("Unpin all"), self.unpin_all)
        if not menu.isEmpty():
            menu.exec(global_pos)

    # ---- export

    def export_board(self) -> Board:
        return Board(positions=self._positions(), pinned=set(self.board.pinned), notes=self.board.notes,
                     links=self.board.links)

    def export_image(self, fmt: str) -> Path | None:
        if self.case is None or self.scene is None:
            return None
        default = case_dir(self.case.id, self.state.evidence.root) / "reports" / f"{self.case.ref}-map.{fmt}"
        path, _ = QFileDialog.getSaveFileName(self, f"Export map as {fmt.upper()}", str(default),
                                              f"{fmt.upper()} (*.{fmt})")
        if not path:
            return None
        path = Path(path if path.lower().endswith(f".{fmt}") else f"{path}.{fmt}")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            render = render_png if fmt == "png" else render_svg
            options = ReportOptions(redact_contacts=True, redact_ips=True)
            clean = (lambda text: redact(text, options)) if self.redact_action.isChecked() else None
            render(self.graph, self.export_board(), path, filt=self.current_filter(), redact=clean)
        except OSError as exc:
            self.state.say(f"Could not save the map: {exc.strerror or exc}.")
            return None
        self.state.say(f"Map saved: {path.name}")
        return path
