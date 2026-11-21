"""Tool library: searchable catalog from tools/*.yaml with category and behavior filters."""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFontMetrics
from PySide6.QtWidgets import QButtonGroup, QFrame, QLabel, QPushButton, QSizePolicy

from app import theme
from app.i18n import tr
from app.state import AppState
from app.widgets import (
    chip_button,
    Banner,
    Card,
    ResponsiveColumns,
    EmptyState,
    KeyValueGrid,
    Screen,
    SearchField,
    Segmented,
    StatusDot,
    button,
    hbox,
    label,
    set_prop,
    tag_row,
    vbox,
)
from core.catalog import Availability, Catalog, availability, filter_tools
from core.manifest import Category, LaunchKind, ToolManifest

BEHAVIOR_OPTIONS = [("any", "Any"), ("local", "Local"), ("external", "External"), ("active", "Active")]
RUNS_AS = {
    LaunchKind.SUBPROCESS: "Separate process",
    LaunchKind.PYTHON: "Python library (built-in module)",
    LaunchKind.WEB_API: "Web API (built-in module)",
    LaunchKind.BROWSER: "Opens in your browser",
}
STATUS_TONE = {
    "Installed": "verified",
    "Built in": "verified",
    "Web API": "uncertain",
    "Opens browser": "muted",
    "Needs key": "lead",
    "Not installed": "rejected",
    "Not integrated": "rejected",
    "Disabled": "red",
}


def _link(url: str, text: str) -> str:
    toks = theme.tokens()
    safe = text.replace("&", "&amp;").replace("<", "&lt;")
    style = f"color:{toks['accent']}; text-decoration:none; font-family:'{toks['mono']}'"
    return f'<a href="{url}" style="{style}">{safe}</a>'


def license_text(tool: ToolManifest) -> str:
    if tool.license:
        return tool.license
    return "license: verify" if tool.open_source else "web service"


def open_official(url: str) -> None:
    """Open a manifest's official link. Only https links from manifests reach here."""
    if url.startswith("https://"):
        QDesktopServices.openUrl(QUrl(url))


def fix_hint(tool: ToolManifest, status: Availability) -> str:
    """The availability detail, phrased as what to do next (core's wording predates Settings and the README)."""
    if status.status == "Not installed" and tool.launch.kind is LaunchKind.SUBPROCESS:
        where = tool.launch.venv or tool.launch.executable
        return (f"Not installed: expected at {where}. See README › Optional tools for the install steps, "
                "then press Reload catalog.")
    if status.status == "Needs key":
        return "Needs an API key: add it in Settings › API keys (stored in Windows Credential Manager)."
    return status.detail


MAX_ROWS = 80  # each row is about 0.2 MB of widgets; hundreds of tools need search, not scrolling


class ToolRow(QFrame):
    """One catalog entry (.tool in the prototype)."""

    selected = Signal(str)

    def __init__(self, tool: ToolManifest, status: Availability):
        super().__init__()
        self.tool = tool
        self.setProperty("toolrow", True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        logo = QLabel(tool.monogram)
        logo.setObjectName("ToolLogo")
        logo.setFixedSize(34, 34)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        name = label(tool.name, "name")
        meta_parts = [tool.category.label, license_text(tool)]
        # Long query URLs would set the list's minimum width and squeeze the detail panel; the full URL is in the panel.
        short = tool.short_url if len(tool.short_url) <= 48 else tool.short_url[:47] + "…"
        meta = QLabel(" · ".join(meta_parts) + " · " + _link(tool.official_url, short))
        meta.setTextFormat(Qt.TextFormat.RichText)
        meta.setProperty("role", "meta")
        meta.linkActivated.connect(open_official)
        middle = vbox(hbox(name, tag_row(tool.display_tags), None, spacing=8), meta, spacing=2)

        self.status_label = label(status.status, "hint")
        self.status_label.setToolTip(fix_hint(tool, status))
        if tool.launch.kind is LaunchKind.BROWSER:
            self.action = button("Open", on_click=lambda: open_official(tool.official_url),
                                 tooltip=f"Open {tool.short_url} in your browser")
        else:
            self.action = button("Details", on_click=lambda: self.selected.emit(tool.id))
        self.action.setAccessibleName(f"{self.action.text()} {tool.name}")

        row = hbox(logo, spacing=12, margins=(16, 12, 16, 12))
        row.addLayout(middle, 1)
        row.addWidget(self.status_label)
        row.addWidget(self.action)
        self.setLayout(row)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.selected.emit(self.tool.id)
        super().mousePressEvent(event)

    def event(self, e: QEvent) -> bool:
        if e.type() in (QEvent.Type.HoverEnter, QEvent.Type.HoverLeave):
            set_prop(self, "hovered", e.type() == QEvent.Type.HoverEnter)
        return super().event(e)


class ToolDetail(Card):
    def __init__(self, state: AppState):
        self.status = StatusDot("", "muted")
        super().__init__("Tool detail", right=[self.status])
        self.state = state
        self.name = label("", "h2")
        self.name.setStyleSheet("font-size: 15px;")
        self.link = QLabel()
        self.link.setTextFormat(Qt.TextFormat.RichText)
        self.link.setProperty("mono", True)
        self.link.linkActivated.connect(open_official)
        self.link.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)  # elided, never widens the card
        self.description = label("", "muted", wrap=True)
        self.facts = KeyValueGrid()
        self.limitations = Banner("warn", "")
        self.availability = label("", "hint", wrap=True)
        self.open_btn = button("Open official site", icon="ext")
        self.settings_btn = button("Open settings", on_click=lambda: state.navigate("settings"))
        for widget in (self.name, self.link, self.description, self.facts, self.limitations, self.availability):
            self.body_layout.addWidget(widget)
        self.body_layout.addLayout(hbox(self.open_btn, self.settings_btn, None, spacing=8))
        self._url = ""
        self.open_btn.clicked.connect(lambda: open_official(self._url))

    def show_tool(self, tool: ToolManifest, status: Availability) -> None:
        self._url = tool.official_url
        self.status.set(status.status, STATUS_TONE.get(status.status, "muted"))
        self.name.setText(tool.name)
        self.link.setToolTip(tool.official_url)
        self._elide_link()
        self.description.setText(tool.description)
        targets = ", ".join(t.label for t in tool.target_types) or "Any (directory)"
        rows: list = [
            ("Category", tool.category.label),
            ("License", tool.license or ("Not verified yet" if tool.open_source else "Web service")),
            ("Open source", "Yes" if tool.open_source else "No"),
            ("Network", tag_row(tool.display_tags[:-1] if tool.open_source else tool.display_tags)),
            ("Targets", targets),
            ("API key", {"none": "Not needed", "optional": "Optional", "required": "Required"}[tool.api_key]),
            ("Runs as", RUNS_AS[tool.launch.kind]),
        ]
        if tool.launch.kind is LaunchKind.SUBPROCESS:
            location = tool.launch.venv or tool.launch.executable
            limits = f"{tool.launch.timeout_s} s timeout · {tool.launch.max_output_kb // 1024 or 1} MB max output"
            rows += [("Location", label(location, mono=True)), ("Limits", limits)]
        rows.append(("Reviewed", f"{tool.review_date:%b} {tool.review_date.day}, {tool.review_date.year}"))
        self.facts.set_rows(rows)
        self.limitations.text.setText(f"<b>Limitations.</b> {tool.limitations}")
        self.availability.setText(fix_hint(tool, status))
        self.settings_btn.setVisible((tool.is_active or status.status == "Needs key") and not status.ready)


    def _elide_link(self) -> None:
        metrics = QFontMetrics(theme.font("mono", 12))
        shown = metrics.elidedText(self._url, Qt.TextElideMode.ElideRight, max(80, self.link.width()))
        self.link.setText(_link(self._url, shown))

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self._url:
            self._elide_link()


class LibraryScreen(Screen):
    title = "Tool Library"

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.rows: dict[str, ToolRow] = {}
        self._selected: str | None = None

        self.reload_btn = button("Reload catalog", icon="rev", on_click=self.reload,
                                 tooltip="Re-read the manifests in tools/ (no network access)")
        _, _, self.summary = self.make_header("Tool library", " ", [self.reload_btn])

        self.errors_banner = Banner("warn", "")
        self.layout_.addWidget(self.errors_banner)

        # ---- filters
        self.search = SearchField("Search tools", kbd="Ctrl F")
        self.search.setFixedWidth(280)
        self.search.edit.textChanged.connect(self.apply_filters)
        self.oss_chip = chip_button("Open source only")
        self.oss_chip.toggled.connect(self.apply_filters)
        self.behavior = Segmented(BEHAVIOR_OPTIONS, current="any")
        self.behavior.changed.connect(lambda _key: self.apply_filters())
        self.layout_.addLayout(hbox(self.search, None, self.oss_chip, self.behavior, spacing=10))

        self.category_group = QButtonGroup(self)
        self.category_group.setExclusive(True)
        self.category_chips: dict[str, QPushButton] = {}
        chips = hbox(spacing=6)
        for key, text in [("", "All")] + [(c.value, c.label) for c in Category]:
            chip = chip_button(text)
            chip.clicked.connect(self.apply_filters)
            self.category_group.addButton(chip)
            self.category_chips[key] = chip
            chips.addWidget(chip)
        chips.addStretch(1)
        self.category_chips[""].setChecked(True)
        self.layout_.addLayout(chips)

        # ---- list + detail
        self.list_card = Card(padding=(0, 0, 0, 0))
        self.list_card.body_layout.setSpacing(0)
        self.list_layout = vbox(spacing=0)
        self.list_card.body_layout.addLayout(self.list_layout)
        self.more = label("", "hint", wrap=True)
        self.more.setContentsMargins(16, 10, 16, 10)
        self.more.hide()
        self.list_card.body_layout.addWidget(self.more)
        self.no_match = EmptyState("search", "No tools match", "Try another search, category or filter.",
                                   [button("Clear filters", on_click=self.clear_filters)])
        self.list_card.body_layout.addWidget(self.no_match)

        self.detail = ToolDetail(state)
        self.detail.setMinimumWidth(300)
        self.columns = ResponsiveColumns(self.list_card, self.detail, breakpoint=1000, side_width=360)
        self.layout_.addWidget(self.columns)
        self.layout_.addStretch(1)

        state.catalog_changed.connect(self.load)
        self.load(state.catalog)

    # ---- data

    def load(self, catalog: Catalog) -> None:
        for row in self.rows.values():
            row.hide()
            row.deleteLater()
        self.rows.clear()

        reviewed = catalog.reviewed
        when = f"catalog reviewed {reviewed:%b %Y}" if reviewed else "no catalog"
        self.summary.setText(f"{len(catalog.tools)} tools · {when} · official links only")
        if catalog.errors:
            items = "<br>".join(f"<b>{e.file}</b>: {_escape(e.message)}" for e in catalog.errors)
            noun = "manifest was" if len(catalog.errors) == 1 else "manifests were"
            self.errors_banner.text.setText(f"{len(catalog.errors)} {noun} skipped. Fix and reload:<br>{items}")
        self.errors_banner.setVisible(bool(catalog.errors))
        if catalog.get(self._selected or "") is None:
            self._selected = None
        self.apply_filters()

    def _make_row(self, tool: ToolManifest) -> ToolRow:
        row = ToolRow(tool, availability(tool, self.state.db))
        row.selected.connect(self.select)
        self.rows[tool.id] = row
        return row

    def reload(self) -> None:
        if not self.reload_btn.isEnabled():
            return
        self.reload_btn.setEnabled(False)
        self.reload_btn.setText(tr("Reloading…"))

        def done(catalog, error) -> None:
            self.reload_btn.setEnabled(True)
            self.reload_btn.setText(tr("Reload catalog"))
            if error is not None:
                self.state.say(f"Couldn't read the tools folder: {error}. Check that tools\\ exists, then reload.")
                return
            skipped = f", {len(catalog.errors)} skipped (see the warning above)" if catalog.errors else ""
            self.state.say(f"Catalog reloaded: {len(catalog.tools)} tools{skipped}.")

        self.state.reload_catalog_in_background(done)

    def on_show(self) -> None:
        # Settings may have changed (active tools) since the rows were built.
        for row in self.rows.values():
            status = availability(row.tool, self.state.db)
            row.status_label.setText(status.status)
            row.status_label.setToolTip(fix_hint(row.tool, status))
        if self._selected:
            self.select(self._selected)

    def focus_search(self) -> None:
        self.search.edit.setFocus()
        self.search.edit.selectAll()

    # ---- filtering and selection

    def current_category(self) -> str:
        return next(key for key, chip in self.category_chips.items() if chip.isChecked())

    def visible_ids(self) -> list[str]:
        return [tool_id for tool_id, row in self.rows.items() if not row.isHidden()]

    def apply_filters(self) -> None:
        matches = filter_tools(
            self.state.catalog.tools,
            query=self.search.edit.text(),
            category=self.current_category() or None,
            behavior=self.behavior.current(),
            open_source_only=self.oss_chip.isChecked(),
        )
        page = matches[:MAX_ROWS]
        shown = {t.id for t in page}
        for tool_id in [i for i in self.rows if i not in shown]:
            row = self.rows.pop(tool_id)
            row.hide()
            row.deleteLater()
        for index, tool in enumerate(page):
            row = self.rows.get(tool.id) or self._make_row(tool)
            self.list_layout.insertWidget(index, row)
            row.show()
            set_prop(row, "last", tool.id == page[-1].id)
        self.more.setText(f"Showing the first {MAX_ROWS} of {len(matches)} tools. Search or pick a category to narrow them.")
        self.more.setVisible(len(matches) > MAX_ROWS)
        self.no_match.setVisible(not matches)
        self.detail.setVisible(bool(matches))
        if matches and self._selected not in shown:
            self.select(matches[0].id)

    def clear_filters(self) -> None:
        self.search.edit.clear()
        self.oss_chip.setChecked(False)
        self.behavior.set_current("any")
        self.category_chips[""].setChecked(True)
        self.apply_filters()

    def select(self, tool_id: str) -> None:
        self._selected = tool_id
        for key, row in self.rows.items():
            set_prop(row, "selected", key == tool_id)
        tool = self.rows[tool_id].tool
        self.detail.show_tool(tool, availability(tool, self.state.db))


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
