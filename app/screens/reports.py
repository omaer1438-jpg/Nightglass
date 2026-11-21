"""Export report: options on the left, live preview on the right (prototype "Reports")."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QCheckBox, QFileDialog, QGridLayout, QLineEdit, QStackedWidget, QTextBrowser, QWidget

from app import theme
from app.state import AppState, run_in_background
from app.widgets import Card, EmptyState, Screen, Segmented, ToggleSwitch, button, hbox, label, vbox
from core.findings import FindingStatus, ResultKind
from core.casemap import MapFilter, build_graph, load_board
from core.evidence import check_file
from core.reports import (FORMATS, ReportError, ReportOptions, default_path, export, redact, render,
                          sidecar)


class ReportsScreen(Screen):
    title = "Reports"

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self._path: Path | None = None
        self._maps: dict = {}  # rendered map PNGs by options; cleared each time the screen is shown
        self._checks: tuple | None = None  # (case id, checked at, {evidence id: result}) from the last hash re-check
        self.pages = QStackedWidget()
        self.layout_.addWidget(self.pages)
        self.layout_.addStretch(1)

        empty = Card()
        empty.body_layout.addWidget(EmptyState(
            "rep", "No case open", "Open a case to export its findings as HTML, Markdown or CSV.",
            [button("Go to dashboard", on_click=lambda: state.navigate("dashboard"))]))
        holder = QWidget()
        holder.setLayout(vbox(empty, None))
        self.pages.addWidget(holder)

        page = QWidget()
        body = vbox(spacing=14)
        page.setLayout(body)
        self.pages.addWidget(page)
        self.heading = label("Export report", "h1")
        self.sub = label("", "sub")
        body.addLayout(vbox(self.heading, self.sub, spacing=2))
        body.addSpacing(6)

        # ---- options
        options = Card(padding=(16, 16, 16, 16))
        self.fmt = Segmented([(k, v) for k, v in FORMATS.items()], current="html")
        self.fmt.changed.connect(lambda _k: self._options_changed(new_path=True))
        self.inc_verified = QCheckBox()
        self.inc_leads = QCheckBox()
        self.inc_rejected = QCheckBox("Rejected findings")
        self.inc_info = QCheckBox("Descriptive data (DNS records, metadata …)")
        self.inc_sources = QCheckBox("Sources, runs and consents")
        self.inc_hashes = QCheckBox("Evidence hashes (SHA-256)")
        self.inc_limits = QCheckBox("Limitations section")
        self.inc_map = QCheckBox("Include case map and analyst notes")
        for box, on in ((self.inc_verified, True), (self.inc_leads, True), (self.inc_rejected, False),
                        (self.inc_info, True), (self.inc_sources, True), (self.inc_hashes, True),
                        (self.inc_limits, True), (self.inc_map, True)):
            box.setChecked(on)
            box.toggled.connect(lambda _on: self._options_changed())
        self.redact_contacts = ToggleSwitch(True, accessible_name="Redact emails and phone numbers")
        self.redact_ips = ToggleSwitch(False, accessible_name="Redact IP addresses")
        for switch in (self.redact_contacts, self.redact_ips):
            switch.toggled.connect(lambda _on: self._options_changed())
        self.save_to = QLineEdit()
        self.save_to.setReadOnly(True)
        self.save_to.setProperty("mono", True)
        self.save_to.setFont(theme.font("mono", 11))
        choose = button("Change…", on_click=self._choose_path)
        self.export_btn = button("Export HTML report", "primary", icon="down", on_click=self.export, name="ExportReport")
        self.open_folder = button("Open reports folder", icon="folder", on_click=self._open_folder)
        self.integrity = label("", "hint", mono=True, wrap=True, selectable=True, name="ReportHash")

        def section(title: str):
            return label(title, "field")

        rows = [
            section("Format"), self.fmt, 6,
            section("Include"), self.inc_verified, self.inc_leads, self.inc_rejected, self.inc_info,
            self.inc_sources, self.inc_hashes, self.inc_limits, self.inc_map, 6,
            section("Redaction"),
            hbox(label("Redact emails and phone numbers"), None, self.redact_contacts),
            hbox(label("Redact IP addresses"), None, self.redact_ips), 6,
            section("Save to"), hbox(self.save_to, choose, spacing=8), 10,
            self.export_btn, self.integrity, self.open_folder,
        ]
        for row in rows:
            if isinstance(row, int):
                options.body_layout.addSpacing(row)
            elif hasattr(row, "addWidget"):
                options.body_layout.addLayout(row)
            else:
                options.body_layout.addWidget(row)
        options.setFixedWidth(380)

        # ---- preview
        self.preview_hint = label("", "hint")
        preview = Card("Preview", right=[self.preview_hint], padding=(14, 14, 14, 14))
        self.preview = QTextBrowser()
        self.preview.setObjectName("ReportPreview")
        self.preview.setOpenLinks(False)
        self.preview.setMinimumHeight(560)
        preview.body_layout.addWidget(self.preview)

        grid = QGridLayout()
        grid.setSpacing(14)
        grid.addWidget(options, 0, 0, Qt.AlignmentFlag.AlignTop)
        grid.addWidget(preview, 0, 1)
        grid.setColumnStretch(1, 1)
        body.addLayout(grid)

        # Rendering a big case takes ~1 s; a hidden screen refreshes when navigated to (MainWindow calls on_show).
        state.active_case_changed.connect(lambda _c: self.on_show() if self.isVisible() else None)

    # ---- state

    def options(self) -> ReportOptions:
        return ReportOptions(
            fmt=self.fmt.current(),
            include_verified=self.inc_verified.isChecked(), include_leads=self.inc_leads.isChecked(),
            include_rejected=self.inc_rejected.isChecked(), include_info=self.inc_info.isChecked(),
            include_sources=self.inc_sources.isChecked(), include_hashes=self.inc_hashes.isChecked(),
            include_limitations=self.inc_limits.isChecked(), include_map=self.inc_map.isChecked(),
            redact_contacts=self.redact_contacts.isChecked(), redact_ips=self.redact_ips.isChecked(),
        )

    def on_show(self) -> None:
        case = self.state.active_case
        self.pages.setCurrentIndex(1 if case else 0)
        if case is None:
            return
        self._maps.clear()  # the case may have changed since the last visit
        self._recheck_evidence(case.id)
        self.integrity.setText("")
        self.sub.setText(f"{case.ref} · {case.name}")
        findings = self.state.findings.list(case.id)
        verified = sum(f.status is FindingStatus.VERIFIED for f in findings)
        leads = sum(f.status is FindingStatus.LEAD and f.result is not ResultKind.INFO for f in findings)
        self.inc_verified.setText(f"Verified findings ({verified})")
        self.inc_leads.setText(f"Leads, clearly labeled ({leads})")
        self._options_changed(new_path=True)

    def _options_changed(self, new_path: bool = False) -> None:
        case = self.state.active_case
        if case is None:
            return
        opts = self.options()
        if new_path or self._path is None:
            self._path = default_path(case.id, case.ref, opts.fmt)
        elif self._path.suffix != f".{opts.fmt}":
            self._path = self._path.with_suffix(f".{opts.fmt}")
        self.save_to.setText(str(self._path))
        self.export_btn.setText(f"Export {FORMATS[opts.fmt]} report")
        # The map is drawn only for a visible preview: this also runs on every case change in the background.
        content = render(self.state.db, case.id, opts, self.map_png(opts) if self.isVisible() else None,
                         checks=self._checks_for(case.id))
        if opts.fmt == "html":
            self.preview.setHtml(content)
            self.preview.setStyleSheet("QTextBrowser#ReportPreview { background: #f4f6f8; color: #16202b; "
                                       "border-radius: 6px; border: none; padding: 8px; }")
        else:
            self.preview.setStyleSheet("")
            self.preview.setPlainText(content)
            self.preview.setFont(theme.font("mono", 12))
        self.preview_hint.setText(f"{len(content.encode('utf-8')) // 1024 + 1} KB")

    def _choose_path(self) -> None:
        fmt = self.fmt.current()
        path, _ = QFileDialog.getSaveFileName(self, "Save report as", str(self._path or ""),
                                              f"{FORMATS[fmt]} (*.{fmt})")
        if path:
            self._path = Path(path) if path.lower().endswith(f".{fmt}") else Path(f"{path}.{fmt}")
            self.save_to.setText(str(self._path))

    def export(self) -> Path | None:
        case = self.state.active_case
        if case is None or self._path is None:
            return None
        try:
            opts = self.options()
            saved = export(self.state.db, case.id, opts, self._path, self.map_png(opts), self._checks_for(case.id))
            digest = sidecar(saved).read_text(encoding="utf-8").split()[0]
        except (ReportError, OSError) as exc:
            self.state.say(str(exc))
            return None
        self.integrity.setText(f"SHA-256 of {saved.name}:\n{digest}")
        self.state.say(f"Report saved: {saved.name} (SHA-256 in {sidecar(saved).name})")
        self._path = default_path(case.id, case.ref, self.fmt.current())  # next export gets a new name
        self.save_to.setText(str(self._path))
        return saved

    def _recheck_evidence(self, case_id: int) -> None:
        """Re-hash the case's evidence files on the thread pool, so the report can say whether they still match."""
        items = [(item.id, item.path, item.sha256) for item in self.state.evidence.list(case_id)]
        if not items:
            self._checks = None
            return

        def done(results, error) -> None:
            if error is None and self.state.active_case is not None and self.state.active_case.id == case_id:
                self._checks = (case_id, datetime.now(timezone.utc).replace(microsecond=0), results)
                self._options_changed()

        run_in_background(lambda: {item_id: check_file(path, sha) for item_id, path, sha in items}, done)

    def _checks_for(self, case_id: int) -> tuple | None:
        return self._checks[1:] if self._checks and self._checks[0] == case_id else None

    def _open_folder(self) -> None:
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._path.parent)))

    def map_png(self, opts: ReportOptions) -> bytes | None:
        """The case map for this report, honouring its include and redaction options (never thumbnails)."""
        case = self.state.active_case
        if case is None or not opts.include_map or opts.fmt == "csv" or QGuiApplication.instance() is None:
            return None
        statuses = {"verified"} if opts.include_verified else set()
        if opts.include_leads:
            statuses |= {"lead", "uncertain"} | ({"info"} if opts.include_info else set())
        if opts.include_rejected:
            statuses.add("rejected")
        kinds = {"target", "finding", "note"} | ({"source"} if opts.include_sources else set()) \
            | ({"evidence"} if opts.include_hashes else set())
        key = (case.id, frozenset(statuses), frozenset(kinds), opts.redact_contacts, opts.redact_ips)
        if key not in self._maps:
            from app.screens.case_map_render import render_png  # Qt rendering lives in the app layer

            board = load_board(self.state.db, case.id)
            graph = build_graph(self.state.db, case.id, board)
            clean = (lambda text: redact(text, opts)) if opts.redact_contacts or opts.redact_ips else None
            self._maps[key] = render_png(graph, board, filt=MapFilter(kinds=kinds, statuses=statuses), redact=clean)
        return self._maps[key]
