"""Case workspace: header, counts, and tabs for findings, targets, evidence, notes, activity."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHeaderView,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from app import formatting, theme
from app.i18n import tr
from app.dialogs import DeleteCaseDialog, EvidenceLinkDialog
from app.screens.case_map import CaseMapPanel
from app.screens.findings_panel import FindingsPanel
from app.state import AppState, run_in_background
from app.widgets import (
    Banner,
    Card,
    EmptyState,
    Screen,
    StatCard,
    StatusDot,
    Tabs,
    button,
    clear_layout,
    hbox,
    label,
    vbox,
)
from core.cases import Case, CaseError
from core.evidence import EvidenceError, check_file
from core.retention import delete_case
from core.runs import case_dir
from core.validation import TargetType, ValidationError


class CaseWorkspaceScreen(Screen):
    title = "Case Workspace"

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.case: Case | None = None
        self._notes_dirty = False

        self.pages = QStackedWidget()
        self.layout_.addWidget(self.pages)
        self.layout_.addStretch(1)

        # ---- no case
        empty = Card()
        empty.body_layout.addWidget(
            EmptyState(
                "case",
                "No case open",
                "Create a case, or open one from the dashboard's recent cases.",
                [
                    button("Go to dashboard", on_click=lambda: state.navigate("dashboard")),
                    button("New case", "primary", icon="plus", on_click=lambda: state.navigate("newcase")),
                ],
            )
        )
        empty_page = QWidget()
        empty_page.setLayout(vbox(empty, None))
        self.pages.addWidget(empty_page)

        # ---- case page
        page = QWidget()
        body = vbox(spacing=14)
        page.setLayout(body)
        self.pages.addWidget(page)

        self.kicker = label("", "hint", mono=True)
        self.heading = label("", "h1", selectable=True)
        self.heading.setWordWrap(True)
        self.scope_line = label("", "sub", wrap=True, selectable=True)
        self.status_dot = StatusDot("Open", "open", 11)
        self.add_evidence = button("Add evidence", icon="clip", on_click=self.add_evidence_file, name="AddEvidence",
                                   tooltip="Copy a file into this case's evidence folder and record its SHA-256")
        self.open_map = button("Open map", icon="tree", on_click=lambda: state.request_tab("map"), name="OpenMap",
                               tooltip="See this case as a board of cards and connections")
        self.export = button("Export", icon="rep", on_click=lambda: state.navigate("reports"),
                             tooltip="Export a report of this case")
        self.delete_btn = button("Delete case", "danger", on_click=self.delete_case, name="DeleteCase",
                                 tooltip="Permanently delete this closed case and its folder")
        self.close_btn = button("Close case", on_click=self.toggle_closed, name="CloseCase",
                                tooltip="Make the case read-only; reopen it any time")
        self.run_btn = button("Run module", "primary", icon="play", on_click=lambda: state.navigate("modules"),
                              tooltip="Pick a module to run on a target in this case")
        titles = vbox(hbox(self.kicker, self.status_dot, None, spacing=10), self.heading, self.scope_line, spacing=2)
        header = hbox(spacing=8)
        header.addLayout(titles, 1)
        for widget in (self.add_evidence, self.open_map, self.export, self.delete_btn, self.close_btn, self.run_btn):
            header.addWidget(widget, 0, Qt.AlignmentFlag.AlignBottom)
        body.addLayout(header)
        body.addSpacing(2)

        self.closed_banner = Banner("warn", "")
        body.addWidget(self.closed_banner)

        self.stat_targets = StatCard("Targets")
        self.stat_findings = StatCard("Findings")
        self.stat_leads = StatCard("Leads", tone="amber")
        self.stat_evidence = StatCard("Evidence files")
        stats = QGridLayout()
        stats.setSpacing(14)
        for col, card in enumerate((self.stat_targets, self.stat_findings, self.stat_leads, self.stat_evidence)):
            stats.addWidget(card, 0, col)
            stats.setColumnStretch(col, 1)
        body.addLayout(stats)

        self.tabs = Tabs()
        self.tabs.add_tab("findings", "Findings", self._findings_page())
        self.tabs.add_tab("targets", "Targets", self._targets_page())
        self.tabs.add_tab("evidence", "Evidence", self._evidence_page())
        self.tabs.add_tab("notes", "Notes", self._notes_page())
        self.tabs.add_tab("activity", "Activity log", self._activity_page())
        self.map_panel = CaseMapPanel(self.state)
        self.tabs.add_tab("map", "Map", self.map_panel)
        body.addWidget(self.tabs)

        QShortcut(QKeySequence.StandardKey.Save, self, activated=self.save_notes)
        state.active_case_changed.connect(self.load)
        state.tab_requested.connect(self.tabs.set_current)
        self.load(state.active_case)

    # ---- pages

    def _findings_page(self) -> QWidget:
        self.findings_panel = FindingsPanel(self.state)
        self.findings_panel.changed.connect(self._findings_changed)
        return self.findings_panel

    def _findings_changed(self) -> None:
        self.state.case_updated(self.state.cases.get_case(self.case.id))

    def _evidence_page(self) -> QWidget:
        self.evidence_table = QTableWidget(0, 5)
        self.evidence_table.setHorizontalHeaderLabels(["FILE", "FINDING", "SHA-256", "ADDED", "CHECK"])
        _style_table(self.evidence_table)
        header = self.evidence_table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for col, width in ((0, 240), (1, 200), (3, 140), (4, 110)):
            self.evidence_table.setColumnWidth(col, width)
        self.evidence_empty = EmptyState(
            "clip", "No evidence files",
            "Add screenshots, exports or other files. Each is copied into this case's evidence folder "
            "and its SHA-256 is recorded, so later changes can be detected.",
        )
        card = Card(padding=(0, 0, 0, 0))
        card.body_layout.setSpacing(0)
        card.body_layout.addWidget(self.evidence_table)
        card.body_layout.addWidget(self.evidence_empty)
        self.verify_btn = button("Verify hashes", icon="shield", on_click=self.verify_evidence, name="VerifyEvidence")
        folder = button("Open evidence folder", icon="folder", on_click=self.open_evidence_folder)
        page = QWidget()
        page.setLayout(vbox(hbox(None, folder, self.verify_btn, spacing=8), card, None, spacing=10))
        self._checks: dict[int, bool | None] = {}
        self._evidence_busy = False  # hashing/copying on a worker thread
        return page

    def _targets_page(self) -> QWidget:
        self.target_type = QComboBox()
        for kind in TargetType:
            self.target_type.addItem(kind.label, kind)
        self.target_type.setMinimumWidth(150)
        self.target_type.setCursor(Qt.CursorShape.PointingHandCursor)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Add a target: example_user, example.com, 192.0.2.10 …")
        self.target_input.returnPressed.connect(self.add_target)
        self.target_input.textChanged.connect(lambda: self.target_error.hide())
        self.add_target_btn = button("Add target", icon="plus", on_click=self.add_target, name="AddTarget")
        self.target_error = label("", "error", wrap=True)
        self.target_error.hide()

        self.targets_table = QTableWidget(0, 4)
        self.targets_table.setHorizontalHeaderLabels(["TYPE", "VALUE", "FINGERPRINT", "ADDED"])
        _style_table(self.targets_table)
        header = self.targets_table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for col, width in ((0, 130), (2, 170), (3, 150)):
            self.targets_table.setColumnWidth(col, width)
        self.targets_empty = EmptyState(
            "user", "No targets yet",
            "Pick a type and enter a username, email, phone, IP, domain or URL above. Modules run on targets.")

        card = Card(padding=(0, 0, 0, 0))
        card.body_layout.setSpacing(0)
        card.body_layout.addWidget(self.targets_table)
        card.body_layout.addWidget(self.targets_empty)

        page = QWidget()
        page.setLayout(
            vbox(hbox(self.target_type, self.target_input, self.add_target_btn, spacing=8), self.target_error,
                 card, None, spacing=10)
        )
        return page

    def _notes_page(self) -> QWidget:
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Working notes for this case. Saved locally with the case.")
        self.notes.setMinimumHeight(240)
        self.notes.textChanged.connect(self._notes_edited)
        self.notes_status = label("", "hint")
        self.save_notes_btn = button("Save notes", "primary", on_click=self.save_notes, name="SaveNotes",
                                     tooltip="Save notes (Ctrl+S)")
        page = QWidget()
        page.setLayout(vbox(self.notes, hbox(self.notes_status, None, label("Ctrl S", "hint", mono=True),
                                             self.save_notes_btn, spacing=10), spacing=10))
        return page

    def _activity_page(self) -> QWidget:
        self.activity_card = Card(padding=(16, 6, 16, 6))
        self.activity_list = vbox(spacing=0)
        self.activity_card.body_layout.addLayout(self.activity_list)
        return self.activity_card

    # ---- loading

    def load(self, case: Case | None) -> None:
        switching = case is None or self.case is None or case.id != self.case.id
        if switching:
            self.flush()
        self.case = case
        if case is None:
            self.pages.setCurrentIndex(0)
            return
        self.pages.setCurrentIndex(1)
        opened = formatting.short_datetime(case.created_at)
        self.kicker.setText(f"{case.ref} · opened {opened}")
        self.status_dot.set("Open" if case.is_open else "Closed", case.status)
        self.heading.setText(case.name)
        self.scope_line.setText(f"Scope: {case.authorized_scope}")
        self.scope_line.setToolTip(f"Purpose: {case.purpose}")
        self.close_btn.setText(tr("Close case" if case.is_open else "Reopen case"))
        self.close_btn.setProperty("variant", None if case.is_open else "primary")
        self.close_btn.style().unpolish(self.close_btn)
        self.close_btn.style().polish(self.close_btn)
        self.run_btn.setVisible(case.is_open)
        self.add_evidence.setVisible(case.is_open)
        self.delete_btn.setVisible(not case.is_open)
        if case.closed_at:
            self.closed_banner.text.setText(
                f"<b>Closed {formatting.short_datetime(case.closed_at)}.</b> This case is read-only. "
                "Reopen it to add targets or edit notes."
            )
        self.closed_banner.setVisible(not case.is_open)

        if switching or (self.notes.toPlainText() != case.notes and not self._notes_dirty):
            self.notes.blockSignals(True)
            self.notes.setPlainText(case.notes)
            self.notes.blockSignals(False)
            self._notes_dirty = False
        self.notes.setReadOnly(not case.is_open)
        self.notes.setProperty("readOnly", not case.is_open)
        self.save_notes_btn.setEnabled(case.is_open)
        self._update_notes_status()
        for widget in (self.target_type, self.target_input, self.add_target_btn):
            widget.setEnabled(case.is_open)
        if switching:
            self.target_input.clear()
            self.tabs.set_current("findings")
        self.refresh_data()

    def refresh_data(self) -> None:
        case = self.case
        if case is None:
            return
        counts = self.state.cases.counts(case.id)
        self.stat_targets.set(counts.targets)
        self.stat_findings.set(counts.findings)
        self.stat_leads.set(counts.leads)
        self.stat_evidence.set(counts.evidence)
        self.tabs.set_count("findings", counts.findings)
        self.tabs.set_count("targets", counts.targets)
        self.tabs.set_count("evidence", counts.evidence)
        self._fill_targets()
        self._fill_activity()
        self._fill_evidence()
        self.findings_panel.load(case)
        self.map_panel.set_case(case)

    def on_show(self) -> None:
        self.refresh_data()

    def focus_search(self) -> None:
        if self.case is not None:
            self.tabs.set_current("findings")
            self.findings_panel.search.edit.setFocus()
            self.findings_panel.search.edit.selectAll()

    def _fill_targets(self) -> None:
        targets = self.state.cases.list_targets(self.case.id)
        table = self.targets_table
        table.setRowCount(len(targets))
        for row, target in enumerate(targets):
            cells = [
                target.type.label,
                target.value,
                f"{target.fingerprint[:8]}…{target.fingerprint[-4:]}",
                formatting.short_datetime(target.created_at),
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col in (1, 2):
                    item.setFont(theme.font("mono", 12))
                if col in (2, 3):
                    item.setForeground(theme.color("muted"))
                if col == 2:
                    item.setToolTip(f"sha256 {target.fingerprint}")
                table.setItem(row, col, item)
        table.setFixedHeight(table.horizontalHeader().height() + 40 * len(targets) + 2)
        table.setVisible(bool(targets))
        self.targets_empty.setVisible(not targets)

    def _fill_activity(self) -> None:
        clear_layout(self.activity_list)
        events = self.state.cases.activity(self.case.id)
        for index, event in enumerate(events):
            row = QWidget()
            if index < len(events) - 1:
                row.setObjectName("ActivityRow")
                row.setStyleSheet(f"#ActivityRow {{ border-bottom: 1px dashed {theme.tokens()['border']}; }}")
            when = label(formatting.short_datetime(event.at), "hint", mono=True)
            when.setFixedWidth(110)
            what = label(event.event)
            detail = label(event.detail, "muted", selectable=True)
            row.setLayout(hbox(when, what, detail, None, spacing=12, margins=(0, 9, 0, 9)))
            self.activity_list.addWidget(row)

    # ---- actions

    def _fill_evidence(self) -> None:
        items = self.state.evidence.list(self.case.id)
        table = self.evidence_table
        table.setRowCount(len(items))
        titles = {f.id: f.title for f in self.state.findings.list(self.case.id)} if items else {}
        for row, item in enumerate(items):
            check = self._checks.get(item.id, "unchecked")
            status = {True: ("Matches", "green"), False: ("CHANGED", "red"), None: ("Missing", "red"),
                      "unchecked": ("Not checked", "dim")}[check]
            finding = titles.get(item.finding_id, "—") if item.finding_id else "—"
            cells = [item.name, finding, item.sha256, formatting.short_datetime(item.collected_at), status[0]]
            for col, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                if col == 1 and not item.finding_id:
                    cell.setForeground(theme.color("dim"))
                if col == 2:
                    cell.setFont(theme.font("mono", 11))
                    cell.setForeground(theme.color("muted"))
                if col == 4:
                    cell.setForeground(theme.color(status[1]))
                cell.setToolTip(text if col == 1 and item.finding_id else (item.description or item.path))
                table.setItem(row, col, cell)
        table.setFixedHeight(table.horizontalHeader().height() + 40 * len(items) + 2)
        table.setVisible(bool(items))
        self.evidence_empty.setVisible(not items)

    def _set_evidence_busy(self, busy_button: QPushButton | None, text: str = "") -> None:
        """Busy state while a worker hashes or copies: both evidence buttons off, the clicked one says why."""
        self._evidence_busy = busy_button is not None
        for btn, idle in ((self.add_evidence, "Add evidence"), (self.verify_btn, "Verify hashes")):
            btn.setEnabled(not self._evidence_busy)
            btn.setText(tr(text if btn is busy_button else idle))

    def add_evidence_file(self) -> None:
        if self.case is None or not self.case.is_open or self._evidence_busy:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Add evidence file", "", "All files (*.*)")
        if not path:
            return
        case_id, name = self.case.id, Path(path).name
        findings = self.state.findings.list(case_id)
        finding_id = None
        if findings:
            on_findings = self.tabs.current() == "findings"
            dialog = EvidenceLinkDialog(self.window(), name, self.case, findings,
                                        self.findings_panel.selected_id if on_findings else None)
            if not dialog.exec():
                return
            finding_id = dialog.finding_id
        try:
            self.state.evidence.check_open(case_id)
        except EvidenceError as exc:
            self.state.say(str(exc))
            return
        self._set_evidence_busy(self.add_evidence, "Adding…")
        self.state.say(f"Hashing and copying {name}…")

        def done(result, error) -> None:
            self._set_evidence_busy(None)
            try:
                if error is not None:
                    raise error
                stored, digest = result
                # The file name only: the full local path would leak into reports.
                item = self.state.evidence.record(case_id, stored, digest, f"Added from {name}", finding_id)
            except Exception as exc:  # EvidenceError (shown as is) or an unexpected worker failure
                self.state.say(str(exc))
                return
            self.state.case_updated(self.state.cases.get_case(case_id))
            if self.case is not None and self.case.id == case_id:
                self.tabs.set_current("evidence")
            self.state.say(f"Evidence added · sha256 {item.sha256[:12]}…")

        run_in_background(lambda: self.state.evidence.copy_in(case_id, path), done)

    def verify_evidence(self) -> None:
        if self.case is None or self._evidence_busy:
            return
        case_id = self.case.id
        items = [(item.id, item.path, item.sha256) for item in self.state.evidence.list(case_id)]
        self._set_evidence_busy(self.verify_btn, "Checking…")

        def done(checks, error) -> None:
            self._set_evidence_busy(None)
            if error is not None:
                self.state.say(f"The hash check failed: {error}. Check that the evidence folder is readable "
                               "(Open evidence folder), then press Verify hashes again.")
                return
            if self.case is None or self.case.id != case_id:
                return
            self._checks = checks
            bad = sum(1 for ok in checks.values() if ok is not True)
            self._fill_evidence()
            self.state.say(f"{len(items) - bad} of {len(items)} evidence files match their recorded SHA-256."
                           + (" Check the ones marked CHANGED or Missing." if bad else ""))

        run_in_background(lambda: {item_id: check_file(path, sha) for item_id, path, sha in items}, done)

    def _refuse_while_busy(self, action: str) -> bool:
        """Closing or deleting a case under a running tool or evidence copy would lose its results."""
        if self.state.runner.has_active_run(self.case.id):
            self.state.say(f"A module is still running in {self.case.ref}. Stop it or wait for it to finish, "
                           f"then {action} the case.")
            return True
        if self._evidence_busy:
            self.state.say(f"Evidence files are still being hashed. Wait a moment, then {action} the case.")
            return True
        return False

    def open_evidence_folder(self) -> None:
        if self.case is not None:
            folder = case_dir(self.case.id) / "evidence"
            folder.mkdir(parents=True, exist_ok=True)
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def delete_case(self) -> None:
        if self.case is None or self.case.is_open or self._refuse_while_busy("delete"):
            return
        dialog = DeleteCaseDialog(self.window(), self.case)
        if not dialog.exec():
            return
        ref = delete_case(self.state.db, self.case.id)
        self.case = None
        self.state.case_deleted()
        self.state.say(f"{ref} and its folder were deleted.")

    def toggle_closed(self) -> None:
        if self.case is None or (self.case.is_open and self._refuse_while_busy("close")):
            return
        self.flush()
        try:
            if self.case.is_open:
                case = self.state.cases.close_case(self.case.id)
                message = f"{case.ref} closed. Reopen it any time from the dashboard or here."
            else:
                case = self.state.cases.reopen_case(self.case.id)
                message = f"{case.ref} reopened."
        except CaseError as exc:
            self.state.say(str(exc))
            return
        self.state.case_updated(case)
        self.state.say(message)

    def add_target(self) -> None:
        if self.case is None or not self.case.is_open:
            return
        kind: TargetType = self.target_type.currentData()
        try:
            self.state.cases.add_target(self.case.id, kind, self.target_input.text())
        except (ValidationError, CaseError) as exc:
            self.target_error.setText(str(exc))
            self.target_error.show()
            self.target_input.setFocus()
            return
        self.target_input.clear()
        self.state.case_updated(self.state.cases.get_case(self.case.id))
        self.state.say(f"Target added to {self.case.ref}.")

    def _notes_edited(self) -> None:
        self._notes_dirty = True
        self._update_notes_status()

    def _update_notes_status(self) -> None:
        if self.case is None:
            return
        if not self.case.is_open:
            self.notes_status.setText("Read-only while the case is closed")
        elif self._notes_dirty:
            self.notes_status.setText("Unsaved changes · saved automatically when you leave this case")
        else:
            self.notes_status.setText(f"Saved {formatting.short_datetime(self.case.updated_at)}")

    def save_notes(self) -> bool:
        if self.case is None or not self.case.is_open or not self._notes_dirty:
            return False
        case = self.state.cases.save_case(self.case.id, notes=self.notes.toPlainText())
        self._notes_dirty = False
        self.case = case
        self.state.case_updated(case)
        self._update_notes_status()
        return True

    def flush(self) -> None:
        """Save pending note edits (called before switching cases and on exit)."""
        if self._notes_dirty and self.case is not None and self.case.is_open:
            self.save_notes()


def _style_table(table: QTableWidget) -> None:
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(40)
    table.setShowGrid(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    header = table.horizontalHeader()
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    header.setHighlightSections(False)
    header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
