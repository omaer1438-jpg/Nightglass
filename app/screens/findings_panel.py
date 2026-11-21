"""Findings tab: filterable table + detail panel with the verification workflow."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont, QFontMetrics, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QComboBox,
    QGridLayout,
    QHeaderView,
    QPlainTextEdit,
    QPushButton,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from app.dialogs import EvidenceDialog
from app import formatting, theme
from app.i18n import tr, tr_status
from app.widgets import (
    Card,
    EmptyState,
    KeyValueGrid,
    SearchField,
    StatusDot,
    WrapText,
    available_width,
    button,
    hbox,
    label,
    tag_row,
    vbox,
)
from core.cases import Case
from core.findings import FindingStatus, StoredFinding

STATUS_KIND = {"Lead": "lead", "Verified": "verified", "Rejected": "rejected", "Uncertain": "uncertain",
               "Info": "muted", "Found": "verified"}
FILTERS = [("", "All"), ("lead", "Leads"), ("verified", "Verified"), ("rejected", "Rejected")]


def _link(url: str) -> str:
    toks = theme.tokens()
    safe = url.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
    return (f'<a href="{safe}" style="color:{toks["accent"]}; text-decoration:none; '
            f"font-family:'{toks['mono']}'\">{safe}</a>")


def open_link(url: str) -> None:
    if url.lower().startswith(("https://", "http://")):
        QDesktopServices.openUrl(QUrl(url))


MAX_ROWS = 2000  # plain items painted by FindingCellDelegate, no widgets per row
SUB_ROLE = Qt.ItemDataRole.UserRole + 1  # FINDING: the line under the title; STATUS: the untranslated status word


class FindingCellDelegate(QStyledItemDelegate):
    """Paints the two-line FINDING cell and the STATUS dot, so rows need no widgets."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        text, opt.text = opt.text, ""
        widget = option.widget
        widget.style().drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, widget)  # QSS background
        rect = option.rect.adjusted(12, 0, -8, 0)
        rtl = option.direction == Qt.LayoutDirection.RightToLeft
        start = Qt.AlignmentFlag.AlignRight if rtl else Qt.AlignmentFlag.AlignLeft
        painter.save()
        if index.column() == 0:
            title_font = theme.font("sans", 13, QFont.Weight.DemiBold)
            sub_font = theme.font("mono", 11)
            half = rect.height() // 2
            painter.setFont(title_font)
            painter.setPen(index.data(Qt.ItemDataRole.ForegroundRole).color())
            painter.drawText(rect.adjusted(0, 0, 0, -half), start | Qt.AlignmentFlag.AlignBottom,
                             QFontMetrics(title_font).elidedText(text, Qt.TextElideMode.ElideRight, rect.width()))
            painter.setFont(sub_font)
            painter.setPen(theme.color("dim"))
            sub = index.data(SUB_ROLE) or ""
            painter.drawText(rect.adjusted(0, half + 1, 0, 0), start | Qt.AlignmentFlag.AlignTop,
                             QFontMetrics(sub_font).elidedText(sub, Qt.TextElideMode.ElideRight, rect.width()))
        else:  # status: the same dot + label as StatusDot
            color = theme.color(StatusDot.TONES.get(STATUS_KIND.get(index.data(SUB_ROLE), "muted"), "muted"))
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            dot_x = rect.right() - 6 if rtl else rect.left()
            painter.drawEllipse(QRectF(dot_x, rect.center().y() - 2.5, 6, 6))
            painter.setPen(color)
            painter.setFont(theme.font("sans", 12))
            painter.drawText(rect.adjusted(0 if rtl else 12, 0, -12 if rtl else 0, 0),
                             start | Qt.AlignmentFlag.AlignVCenter, text)
        painter.restore()


class FindingsPanel(QWidget):
    changed = Signal()

    def __init__(self, state):
        super().__init__()
        self.state = state
        self.case: Case | None = None
        self.rows: list[StoredFinding] = []
        self.selected_id: int | None = None

        self.search = SearchField("Filter findings", kbd="Ctrl F")
        self.search.setFixedWidth(280)
        self.search.edit.textChanged.connect(self.refresh)
        self.filter_group = QButtonGroup(self)
        self.filter_chips: dict[str, QPushButton] = {}
        chips = hbox(spacing=6)
        for key, text in FILTERS:
            chip = QPushButton(tr(text))
            chip.setProperty("chip", True)
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.setFocusPolicy(Qt.FocusPolicy.TabFocus)
            chip.clicked.connect(self.refresh)
            self.filter_group.addButton(chip)
            self.filter_chips[key] = chip
            chips.addWidget(chip)
        self.filter_chips[""].setChecked(True)
        self.module_box = QComboBox()
        self.module_box.setMinimumWidth(170)
        self.module_box.currentIndexChanged.connect(self.refresh)
        filters = hbox(self.search, chips, None, label("Module", "meta"), self.module_box, spacing=10)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["FINDING", "MODULE", "SOURCE", "COLLECTED", "CONFIDENCE", "STATUS"])
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(50)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.table.setMinimumHeight(420)
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setHighlightSections(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setMinimumSectionSize(60)
        for col, width in ((1, 110), (2, 120), (3, 92), (4, 100), (5, 104)):
            self.table.setColumnWidth(col, width)
        self._delegate = FindingCellDelegate(self.table)
        self.table.setItemDelegateForColumn(0, self._delegate)
        self.table.setItemDelegateForColumn(5, self._delegate)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table_card = Card(padding=(0, 0, 0, 0))
        self.table_card.body_layout.addWidget(self.table)
        self.empty = EmptyState(
            "search", "No findings yet",
            "Run a module to collect results. Every result is saved as a lead until you verify it; "
            "a match is never proof of identity.",
            [button("Open modules", icon="mod", on_click=lambda: state.navigate("modules"))],
        )
        self.no_match = EmptyState("search", "No findings match",
                                   "Try another word, status or module, or clear the filters to see every finding.",
                                   [button("Clear filters", on_click=self.clear_filters, name="ClearFindingFilters")])
        self.table_card.body_layout.addWidget(self.no_match)
        self.more = label("", "hint", wrap=True)
        self.more.setContentsMargins(16, 10, 16, 10)
        self.more.hide()
        self.table_card.body_layout.addWidget(self.more)
        self.table_card.body_layout.addWidget(self.empty)

        self.detail = FindingDetail(state)
        self.detail.changed.connect(self._detail_changed)
        self.d_note, self.btn_verify = self.detail.d_note, self.detail.btn_verify  # used by tests and callers

        self.grid = QGridLayout()
        self.grid.setSpacing(14)
        self._stacked: bool | None = None
        self._place_detail(stacked=False)
        self.setLayout(vbox(filters, self.grid, None, spacing=12))

    def _place_detail(self, stacked: bool) -> None:
        """Detail beside the table when there's room, below it when the window is narrow."""
        if stacked == self._stacked:
            return
        self._stacked = stacked
        for widget in (self.table_card, self.detail):
            self.grid.removeWidget(widget)
        self.grid.addWidget(self.table_card, 0, 0, Qt.AlignmentFlag.AlignTop)
        if stacked:
            self.grid.addWidget(self.detail, 1, 0, Qt.AlignmentFlag.AlignTop)
            self.detail.setMaximumWidth(16777215)
            self.grid.setColumnStretch(1, 0)
        else:
            self.grid.addWidget(self.detail, 0, 1, Qt.AlignmentFlag.AlignTop)
            self.detail.setMaximumWidth(340)
        self.grid.setColumnStretch(0, 1)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._place_detail(stacked=available_width(self) < 1000)

    # ---- data

    def load(self, case: Case | None) -> None:
        switching = case is None or self.case is None or case.id != self.case.id
        self.case = case
        if switching:
            self.selected_id = None
            self.search.edit.blockSignals(True)
            self.search.edit.clear()
            self.search.edit.blockSignals(False)
            self.filter_chips[""].setChecked(True)
        self.refresh()

    def clear_filters(self) -> None:
        for widget in (self.search.edit, self.module_box):
            widget.blockSignals(True)
        self.search.edit.clear()
        self.module_box.setCurrentIndex(0)
        for widget in (self.search.edit, self.module_box):
            widget.blockSignals(False)
        self.filter_chips[""].setChecked(True)
        self.refresh()

    def current_status(self) -> str:
        return next(k for k, chip in self.filter_chips.items() if chip.isChecked())

    def refresh(self) -> None:
        if self.case is None:
            return
        store = self.state.findings
        modules = store.modules(self.case.id)
        current_module = self.module_box.currentData()
        self.module_box.blockSignals(True)
        self.module_box.clear()
        self.module_box.addItem("Any", "")
        for name in modules:
            self.module_box.addItem(name, name)
        index = self.module_box.findData(current_module) if current_module else 0
        self.module_box.setCurrentIndex(max(index, 0))
        self.module_box.blockSignals(False)

        total = self.state.cases.counts(self.case.id).findings
        matched = store.list(self.case.id, status=self.current_status() or None,
                             module=self.module_box.currentData() or None, query=self.search.edit.text())
        self.rows = matched[:MAX_ROWS]
        self.more.setText(f"Showing the first {MAX_ROWS} of {len(matched)}. Search or filter to reach the rest; "
                          "reports include all of them.")
        self.more.setVisible(len(matched) > MAX_ROWS)
        self._fill_table()
        self.empty.setVisible(total == 0)
        self.table.setVisible(total > 0 and bool(self.rows))
        self.no_match.setVisible(total > 0 and not self.rows)
        self.detail.setVisible(total > 0)
        if self.rows:
            target = self.selected_id if any(r.id == self.selected_id for r in self.rows) else self.rows[0].id
            self.select(target)
        else:
            self.selected_id = None
            self.detail.setVisible(False)

    def _fill_table(self) -> None:
        table = self.table
        table.blockSignals(True)
        table.setUpdatesEnabled(False)
        table.clearContents()
        table.setRowCount(len(self.rows))
        colors = {name: theme.color(name) for name in ("text", "muted", "dim")}
        mono = theme.font("mono", 12)
        for row, finding in enumerate(self.rows):
            dim = finding.status is FindingStatus.REJECTED
            title = QTableWidgetItem(finding.title)
            title.setData(SUB_ROLE, (finding.url or finding.value or "").removeprefix("https://").removeprefix("http://")[:200])
            title.setForeground(colors["dim" if dim else "text"])
            title.setToolTip(finding.title)
            table.setItem(row, 0, title)
            values = [finding.module, finding.source, formatting.clock_time(finding.collected_at),
                      finding.confidence.value.capitalize() if not dim else "—"]
            for col, value in enumerate(values, start=1):
                item = QTableWidgetItem(value)
                if col == 3:
                    item.setFont(mono)
                item.setForeground(colors["dim" if dim else ("muted" if col == 3 else "text")])
                table.setItem(row, col, item)
            status = finding.display_status
            status_item = QTableWidgetItem(tr_status(status))
            status_item.setData(SUB_ROLE, status)
            table.setItem(row, 5, status_item)
        table.setUpdatesEnabled(True)
        table.blockSignals(False)

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.select(self.rows[rows[0].row()].id, from_table=True)

    def select(self, finding_id: int, from_table: bool = False) -> None:
        self.selected_id = finding_id
        if not from_table:
            index = next((i for i, r in enumerate(self.rows) if r.id == finding_id), None)
            if index is not None:
                self.table.blockSignals(True)
                self.table.selectRow(index)
                self.table.blockSignals(False)
        self.detail.show_finding(finding_id, bool(self.case and self.case.is_open))

    def _detail_changed(self) -> None:
        self.refresh()
        self.changed.emit()


class FindingDetail(Card):
    """Finding detail with the verification workflow; shared by the Findings tab and the Case Map."""

    changed = Signal()  # the shown finding's status changed (already saved)

    def __init__(self, state):
        self.detail_status = StatusDot("", "muted")
        super().__init__("Finding detail", right=[self.detail_status])
        self.state = state
        self.finding_id: int | None = None
        self.setMinimumWidth(300)
        self.d_title = label("", "h2", wrap=True, selectable=True)
        self.d_link = WrapText(mono=True, tone="accent")
        self.d_link.link.connect(open_link)
        self.d_value = WrapText(mono=True)
        self.d_facts = KeyValueGrid()
        self.d_note = QPlainTextEdit()
        self.d_note.setPlaceholderText("How did you verify (or reject) this?")
        self.d_note.setFixedHeight(80)
        self.d_note.setTabChangesFocus(True)
        self.btn_verify = button("Mark verified", on_click=lambda: self._set(FindingStatus.VERIFIED), name="MarkVerified")
        self.btn_verify.setStyleSheet(f"color: {theme.tokens()['green']};")
        self.btn_lead = button("Keep as lead", on_click=lambda: self._set(FindingStatus.LEAD), name="KeepLead")
        self.btn_reject = button("Reject", "ghost", on_click=lambda: self._set(FindingStatus.REJECTED), name="Reject")
        self.btn_reject.setStyleSheet(f"color: {theme.tokens()['red']};")
        self.btn_evidence = button("View evidence", icon="search", on_click=self._show_evidence, name="ViewEvidence")
        self.d_hint = label("", "hint", wrap=True)
        for widget in (self.d_title, self.d_link, self.d_value, self.d_facts, self.btn_evidence,
                       label("Verification note", "field"),
                       self.d_note):
            self.body_layout.addWidget(widget)
        self.body_layout.addLayout(hbox(self.btn_verify, self.btn_lead, self.btn_reject, None, spacing=6))
        self.body_layout.addWidget(self.d_hint)

    def show_finding(self, finding_id: int, editable: bool) -> None:
        # A live refresh of the same finding must not wipe a verification note that is still being typed.
        keep_note = finding_id == self.finding_id and self.d_note.document().isModified()
        self.finding_id = finding_id
        finding = self.state.findings.get(finding_id)
        status = finding.display_status
        self.detail_status.set(status, STATUS_KIND[status])
        self.d_title.setText(finding.title)
        self.d_link.setHtml(_link(finding.url) if finding.url else "")
        self.d_link.setVisible(bool(finding.url))
        self.d_value.setPlainText(finding.value or "")
        self.d_value.setVisible(bool(finding.value) and finding.value != finding.url)
        spec = next((m for m in self.state.modules if m.name == finding.module), None)
        rows: list = [
            ("Module", spec.title if spec else finding.module),
            ("Source", finding.source),
            ("Collected", formatting.long_datetime(finding.collected_at)),
            ("Confidence", finding.confidence.value.capitalize()),
            ("Result", finding.result.value.capitalize()),
        ]
        if spec:
            rows.append(("Network", tag_row([t for t in spec.labels if t != "oss"])))
        if finding.run_id:
            rows.append(("Run", label(f"r-{finding.run_id:04d}", mono=True)))
        self.d_facts.set_rows(rows)
        if not keep_note:
            self.d_note.setPlainText(finding.notes)
            self.d_note.document().setModified(False)
        for widget in (self.btn_verify, self.btn_lead, self.btn_reject, self.d_note):
            widget.setEnabled(editable)
        self.d_hint.setText("" if editable else "Reopen the case to change findings.")
        self.d_hint.setVisible(not editable)

    def _show_evidence(self) -> None:
        finding = self.state.findings.get(self.finding_id)
        run = self.state.run_store.get(finding.run_id) if finding.run_id else None
        EvidenceDialog(self.window(), finding, run).exec()

    def _set(self, status: FindingStatus) -> None:
        if self.finding_id is None:
            return
        try:
            self.state.findings.set_status(self.finding_id, status, self.d_note.toPlainText())
        except ValueError as exc:
            self.state.say(str(exc))
            return
        self.d_note.document().setModified(False)  # saved with the status
        self.state.say(f"Finding marked {status.value}.")
        self.changed.emit()
