"""Run Console: live output of the current module run, as a console or a table."""

from __future__ import annotations

import os
import time

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QGridLayout,
    QHeaderView,
    QPlainTextEdit,
    QProgressBar,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from app import theme
from app.dialogs import EvidenceDialog
from app.i18n import tr_status
from app.runs import ActiveRun
from app.screens.findings_panel import SUB_ROLE, FindingCellDelegate
from app.state import AppState
from app.widgets import (
    Banner,
    Card,
    EmptyState,
    Screen,
    Segmented,
    button,
    clear_layout,
    hbox,
    label,
    tag_row,
    vbox,
)
from core.findings import ResultKind

MAX_ROWS = 2000  # plain items; the case keeps them all
TAG_TOKENS = {"g": "green", "y": "amber", "b": "blue", "r": "red", "c": "accent", "p": "dim"}
STATUS_TEXT = {
    "succeeded": ("Finished", "verified"),
    "failed": ("Failed", "red"),
    "timed_out": ("Timed out", "lead"),
    "cancelled": ("Stopped", "rejected"),
}


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class RunConsoleScreen(Screen):
    title = "Run Console"

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.view: ActiveRun | None = None
        self._started = 0.0
        self._row_ids: list[int] = []

        self.pages = QStackedWidget()
        self.layout_.addWidget(self.pages)
        self.layout_.addStretch(1)

        empty = Card()
        empty.body_layout.addWidget(EmptyState(
            "play", "No run yet",
            "Pick a module to run against a target in the active case. Output streams here, "
            "and every result is saved to the case as a lead.",
            [button("Open modules", "primary", icon="mod", on_click=lambda: state.navigate("modules"))],
        ))
        empty_page = QWidget()
        empty_page.setLayout(vbox(empty, None))
        self.pages.addWidget(empty_page)

        page = QWidget()
        body = vbox(spacing=14)
        page.setLayout(body)
        self.pages.addWidget(page)

        # header
        self.kicker = label("", "hint", mono=True)
        self.heading = label("", "h1")
        self.sub = label("", "sub", wrap=True)
        self.sub.setTextFormat(Qt.TextFormat.RichText)
        self.view_toggle = Segmented([("console", "Console"), ("table", "Table")])
        self.view_toggle.changed.connect(self._switch_view)
        self.stop_btn = button("Stop", "danger", on_click=state.runner.stop, name="StopRun")
        self.again_btn = button("Run again", "primary", icon="play", on_click=self._run_again, name="RunAgain")
        header = hbox(spacing=8)
        header.addLayout(vbox(self.kicker, self.heading, self.sub, spacing=2), 1)
        for widget in (self.view_toggle, self.stop_btn, self.again_btn):
            header.addWidget(widget, 0, Qt.AlignmentFlag.AlignBottom)
        body.addLayout(header)

        # status strip
        status_card = Card(padding=(16, 12, 16, 14))
        self.tags_holder = hbox(spacing=4)
        self.status_text = label("", "muted", mono=True)
        status_card.body_layout.addLayout(hbox(self.tags_holder, None, self.status_text, spacing=8))
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        status_card.body_layout.addWidget(self.progress)
        body.addWidget(status_card)

        # console / table + side column
        self.console = QPlainTextEdit()
        self.console.setObjectName("Console")
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(380)
        self.console.setMaximumBlockCount(20000)
        self.console.setFont(theme.font("mono", 12))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["FINDING", "RESULT", "VALUE", "CONFIDENCE", "EVIDENCE"])
        self.table.cellClicked.connect(self._cell_clicked)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        header_view = self.table.horizontalHeader()
        header_view.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header_view.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(3, 110)
        self.table.setColumnWidth(4, 90)
        self.table.setItemDelegateForColumn(1, FindingCellDelegate(self.table))
        self.table_empty = EmptyState("play", "No results to show",
                                      "Results appear here when the run finishes. If it saved nothing, the console "
                                      "says why.")
        table_card = Card(padding=(0, 0, 0, 0))
        table_card.body_layout.addWidget(self.table)
        table_card.body_layout.addWidget(self.table_empty)
        table_card.setMinimumHeight(380)
        self.output = QStackedWidget()
        self.output.addWidget(self.console)
        self.output.addWidget(table_card)

        self.summary_card = Card("Summary")
        self.summary_grid = QGridLayout()
        self.summary_grid.setSpacing(6)
        self.summary_card.body_layout.addLayout(self.summary_grid)
        self.log_card = Card("Run log")
        self.log_text = label("", "muted", mono=True, selectable=True)
        self.log_text.setStyleSheet("font-size: 11px;")
        self.log_text.setWordWrap(True)
        self.log_card.body_layout.addWidget(self.log_text)
        self.open_folder = button("Open run folder", icon="folder", on_click=self._open_folder)
        self.log_card.body_layout.addWidget(self.open_folder)
        self.lead_banner = Banner("warn", "Found results are saved as <b>leads</b>. Verify each one before it "
                                          "goes into a report.")
        self.open_case_btn = button("Open findings in case", on_click=self._open_case)
        side = vbox(self.summary_card, self.log_card, self.lead_banner, self.open_case_btn, None, spacing=14)
        side_host = QWidget()
        side_host.setLayout(side)
        side_host.setFixedWidth(300)

        columns = QGridLayout()
        columns.setSpacing(14)
        columns.addWidget(self.output, 0, 0)
        columns.addWidget(side_host, 0, 1, Qt.AlignmentFlag.AlignTop)
        columns.setColumnStretch(0, 1)
        body.addLayout(columns)

        self._pending: list[list[tuple[str, str]]] = []
        self._formats: dict[str, QTextCharFormat] = {}
        self._flush_timer = QTimer(self, singleShot=True, interval=50)  # batch a fast stream into ~20 paints/s
        self._flush_timer.timeout.connect(self._flush)
        self._tick = QTimer(self, interval=1000)
        self._tick.timeout.connect(self._update_status)
        state.runner.started.connect(self.show_run)
        state.runner.line.connect(self._append)
        state.runner.finished.connect(self._finished)

    # ---- run lifecycle

    def show_run(self, run: ActiveRun) -> None:
        self.view = run
        self._started = time.monotonic()
        self.pages.setCurrentIndex(1)
        view = self.state.db.get_setting("results_view", "console")  # Settings → Appearance → Results view
        self.view_toggle.set_current(view if view in self.view_toggle.buttons else "console")
        self._switch_view(self.view_toggle.current())
        case_ref = run.case.ref
        self.kicker.setText(f"{case_ref} · module {run.spec.number}")
        self.heading.setText(run.spec.name)
        shown = os.path.basename(run.target.value) if run.target.type.value == "file" else run.target.value
        self.sub.setText(
            f'Target <span style="font-family:\'{theme.tokens()["mono"]}\'; color:{theme.tokens()["text"]}">'
            f"{_escape(shown)}</span> · {_escape(run.source)} · timeout {run.timeout_s} s"
        )
        self.sub.setToolTip(run.target.value)
        clear_layout(self.tags_holder)
        self.tags_holder.addWidget(tag_row(run.spec.labels))
        self._pending = []
        self.console.clear()
        prompt = f"nightglass@{case_ref.lower()}:~$ "
        command = f"run {run.spec.id} --target {run.target.value}" + (f" --tool {run.tool.id}" if run.tool else "")
        self._write([(prompt, "dim"), (command, "accent")])
        mode = " · ".join(t.upper() for t in run.spec.labels if t != "oss")
        consent = f"consent {run.consent.ref} logged · " if run.consent else ""
        self._line(f"[i] {consent}mode {mode}", "p")
        self._line(f"[i] timeout {run.timeout_s}s · max output {run.max_output_kb // 1024 or 1} MB"
                   f" · work dir {os.path.basename(run.run.work_dir)}", "p")
        for text, tag in run.lines:
            self._line(text, tag)
        self._flush()
        self.progress.setRange(0, 0)  # busy until finished
        self.table.setRowCount(0)
        self.table.hide()
        self.table_empty.show()
        self._fill_summary({})
        self._update_status()
        self._update_buttons()
        self._tick.start()

    def _append(self, text: str, tag: str) -> None:
        self._line(text, tag)

    def _finished(self, run: ActiveRun) -> None:
        self._tick.stop()
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        outcome = run.outcome
        result = run.result
        saved = len(run.finding_ids)
        if outcome.error:
            self._line(f"[!] {outcome.error}", "r" if run.run.status == "failed" else "y")
        leads = sum(1 for f in (result.findings if result else []) if f.result is not ResultKind.INFO)
        if saved:
            noun = "lead" if leads == 1 else "leads"
            detail = f"{leads} {noun}" if leads else f"{saved} findings"
            self._line(f"\n[!] {detail} saved to {run.case.ref} — verify before drawing conclusions.", "y")
        else:
            self._line("[i] Nothing was saved to the case.", "p")
        self._flush()
        self._fill_summary(result.counts if result else {})
        self._fill_table(run)
        self._update_status()
        self._update_buttons()

    def on_show(self) -> None:
        current = self.state.runner.current
        if current is not None and current is not self.view:
            self.show_run(current)
            if not current.running:
                self._finished(current)
        self.pages.setCurrentIndex(1 if self.view else 0)

    # ---- rendering

    def _line(self, text: str, tag: str) -> None:
        self._write([(text, TAG_TOKENS.get(tag, "console-text"))])

    def _write(self, segments: list[tuple[str, str]]) -> None:
        """Queue one console line of (text, color token) segments; _flush paints the queue in one go."""
        self._pending.append(segments)
        if not self._flush_timer.isActive():
            self._flush_timer.start()

    def _flush(self) -> None:
        # One edit block of plain text with char formats: 20,000 lines take ~0.2 s instead of ~6 s of appendHtml.
        self._flush_timer.stop()
        pending, self._pending = self._pending, []
        if not pending:
            return
        document = self.console.document()
        cursor = QTextCursor(document)
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.beginEditBlock()
        for segments in pending:
            if not document.isEmpty():
                cursor.insertBlock()
            for text, token in segments:
                if token not in self._formats:
                    self._formats[token] = QTextCharFormat()
                    self._formats[token].setForeground(theme.color(token))
                cursor.insertText(text, self._formats[token])
        cursor.endEditBlock()
        self.console.moveCursor(QTextCursor.MoveOperation.End)

    def _update_status(self) -> None:
        run = self.view
        if run is None:
            return
        if run.running:
            elapsed = int(time.monotonic() - self._started)
            self.status_text.setText(f"Running · {elapsed // 60:02d}:{elapsed % 60:02d} · "
                                     f"{len(run.lines)} lines")
            self.log_text.setText(f"status: running\nwork_dir: {_short(run.run.work_dir)}")
            return
        record, outcome = run.run, run.outcome
        text, _tone = STATUS_TEXT.get(record.status, (record.status, "muted"))
        self.status_text.setText(f"{text} · {outcome.duration_s:.1f} s · {len(run.lines)} lines")
        consent = f"\nconsent: {run.consent.ref} ✓" if run.consent else "\nconsent: not needed (local)"
        self.log_text.setText(
            f"status: {record.status}\nexit_code: {record.exit_code if record.exit_code is not None else '—'}\n"
            f"duration: {outcome.duration_s:.1f} s\n"
            f"output: {record.output_bytes // 1024} KB / {run.max_output_kb} KB\n"
            f"work_dir: {_short(record.work_dir)}{consent}"
        )

    def _fill_summary(self, counts: dict) -> None:
        clear_layout(self.summary_grid)
        if not counts:
            counts = {"found": 0, "uncertain": 0, "not_found": 0} if self.view and self.view.tool else {}
        tones = {"found": "green", "uncertain": "blue", "not_found": "dim", "gps": "amber"}
        for col, (key, value) in enumerate(list(counts.items())[:3]):
            number = label(str(value), "stat-v")
            number.setStyleSheet(f"font-size: 22px; color: {theme.tokens()[tones.get(key, 'text')]};")
            number.setAlignment(Qt.AlignmentFlag.AlignCenter)
            caption = label(key.replace("_", " ").capitalize(), "hint")
            caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.summary_grid.addWidget(number, 0, col)
            self.summary_grid.addWidget(caption, 1, col)
        self.summary_card.setVisible(bool(counts))

    def _fill_table(self, run: ActiveRun) -> None:
        findings = self.state.findings.list(run.case.id, run_id=run.run.id)[:MAX_ROWS]
        self._row_ids = [finding.id for finding in findings]
        self.table.setRowCount(len(findings))
        self.table.setVisible(bool(findings))
        self.table_empty.setVisible(not findings)
        for row, finding in enumerate(findings):
            self.table.setItem(row, 0, QTableWidgetItem(finding.title))
            word = {"found": "Found", "uncertain": "Uncertain", "info": "Info"}[finding.result.value]
            result = QTableWidgetItem(tr_status(word))
            result.setData(SUB_ROLE, word)  # painted as a status dot by the findings delegate
            self.table.setItem(row, 1, result)
            value = QTableWidgetItem(finding.url or finding.value or "—")
            value.setFont(theme.font("mono", 12))
            value.setForeground(theme.color("accent" if finding.url else "muted"))
            value.setToolTip(finding.notes)
            self.table.setItem(row, 2, value)
            self.table.setItem(row, 3, QTableWidgetItem(finding.confidence.value.capitalize()))
            evidence = QTableWidgetItem("View")
            evidence.setForeground(theme.color("accent"))
            evidence.setToolTip("See where this result came from")
            self.table.setItem(row, 4, evidence)

    def _cell_clicked(self, row: int, column: int) -> None:
        if column == 4 and self.view is not None:
            EvidenceDialog(self.window(), self.state.findings.get(self._row_ids[row]), self.view.run).exec()

    def _update_buttons(self) -> None:
        running = bool(self.view and self.view.running)
        self.stop_btn.setEnabled(running)
        self.again_btn.setEnabled(not running and self.view is not None)
        self.open_case_btn.setEnabled(not running)
        self.lead_banner.setVisible(bool(self.view and self.view.spec.is_external))

    def _switch_view(self, key: str) -> None:
        self.output.setCurrentIndex(0 if key == "console" else 1)

    # ---- actions

    def _run_again(self) -> None:
        from app.run_flow import launch_module

        if self.view is None:
            return
        case = self.state.active_case
        target = self.view.target
        if case is None or case.id != self.view.case.id:
            self.state.open_case(self.view.case.id, navigate=False)
        launch_module(self.window(), self.state, self.view.spec, target=target, engine_id=self.view.engine.id)

    def _open_case(self) -> None:
        if self.view is not None:
            self.state.open_case(self.view.case.id)
            self.state.request_tab("findings")

    def _open_folder(self) -> None:
        if self.view is not None and self.view.run.work_dir:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.view.run.work_dir))


def _short(path: str | None) -> str:
    if not path:
        return "—"
    parts = path.replace("/", "\\").split("\\")
    return "\\".join(parts[-3:])
