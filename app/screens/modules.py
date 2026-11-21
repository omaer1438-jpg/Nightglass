"""Modules: numbered module grid, plus a Links view for the browser-only tools."""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QButtonGroup, QFrame, QGraphicsOpacityEffect, QGridLayout, QLabel, QPushButton, QWidget

from app import icons, theme
from app.run_flow import launch_module
from app.state import AppState
from app.widgets import (
    Banner,
    EmptyState,
    Screen,
    SearchField,
    Segmented,
    button,
    chip_button,
    hbox,
    label,
    legend_html,
    set_prop,
    tag_row,
    vbox,
)
from core.manifest import LaunchKind, ToolManifest
from core.modules import ModuleSpec, module_status

LEGEND = [
    ("local", "runs offline"),
    ("external", "sends to a third party"),
    ("passive", "public data only"),
    ("active", "touches target systems · off by default"),
    ("api_key", "needs a key"),
]
FIX_HINTS = {  # appended to a card's reason so it says what to do next
    "Not installed": " Install steps: README › Optional tools, then Tool Library › Reload catalog.",
    "Needs key": " Settings › API keys.",
}
CARD_MIN_WIDTH = 240
LINK_MAX = 60  # hundreds of links in the catalog; a page of 60 builds in ~0.25 s (120 took ~0.55 s)
TARGET_FILTERS = [("", "All targets"), ("username", "Username"), ("email", "Email"), ("phone", "Phone"), ("ip", "IP"),
                  ("domain", "Domain"), ("url", "URL"), ("file", "File")]
MODE_FILTERS = [("", "Any mode"), ("local", "Local"), ("external", "External"), ("passive", "Passive"), ("active", "Active")]


class ModuleCard(QFrame):
    clicked = Signal(str)

    def __init__(self, spec: ModuleSpec):
        super().__init__()
        self.spec = spec
        self.setProperty("modcard", True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setAccessibleName(f"{spec.title}: {spec.description}")
        self.glyph = QLabel()
        self.glyph.setProperty("modicon", True)
        self.glyph.setFixedSize(30, 30)
        self.glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        number = label(spec.number, "hint", mono=True)
        name = label(spec.name, "name")
        self.state_tag = QLabel()
        top = hbox(self.glyph, vbox(number, name, spacing=0), None, self.state_tag, spacing=10)
        description = label(spec.description, "meta", wrap=True)
        description.setMinimumHeight(34)
        description.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.reason = label("", "hint", wrap=True)
        self.setLayout(vbox(top, description, tag_row(spec.labels), self.reason, spacing=10, margins=(14, 14, 14, 14)))
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)

    def set_status(self, ready: bool, status_label: str, reason: str) -> None:
        reason += FIX_HINTS.get(status_label, "") if not ready else ""
        off = self.spec.is_active and status_label == "Off"
        set_prop(self.glyph, "off", off)
        self.glyph.setPixmap(icons.pixmap(self.spec.icon, "red" if off else "accent", 16))
        self.state_tag.setText(("Off" if off else status_label).upper())
        set_prop(self.state_tag, "tag", "active" if off else "oss")
        self.state_tag.setVisible(not ready)
        self.reason.setText("" if ready else reason)
        self.reason.setVisible(not ready)
        self._effect.setOpacity(1.0 if ready else 0.55)
        self.setToolTip(reason)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.spec.id)

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            self.clicked.emit(self.spec.id)
            return
        super().keyPressEvent(event)

    def event(self, e: QEvent) -> bool:
        if e.type() in (QEvent.Type.HoverEnter, QEvent.Type.HoverLeave):
            set_prop(self, "hovered", e.type() == QEvent.Type.HoverEnter)
        return super().event(e)


class LinkCard(QFrame):
    """A browser-only catalog tool: clicking opens its official site. Nothing runs or is saved."""

    def __init__(self, tool: ToolManifest):
        super().__init__()
        self.tool = tool
        self.setProperty("modcard", True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setAccessibleName(f"{tool.name}: opens {tool.short_url} in your browser")
        logo = QLabel(tool.monogram)
        logo.setObjectName("ToolLogo")
        logo.setFixedSize(30, 30)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        category = label(tool.category.label, "hint")
        name = label(tool.name, "name", wrap=True)
        top = hbox(logo, vbox(category, name, spacing=0), None, spacing=10)
        description = label(tool.description, "meta", wrap=True)
        description.setMinimumHeight(34)
        description.setAlignment(Qt.AlignmentFlag.AlignTop)
        url = tool.short_url if len(tool.short_url) <= 34 else tool.short_url[:33] + "…"  # full URL in the tooltip
        opens = label(f"Opens {url} ↗", "hint")
        self.setLayout(vbox(top, description, tag_row(tool.display_tags), opens, spacing=10, margins=(14, 14, 14, 14)))
        self.setToolTip(f"Opens {tool.official_url}")

    def _open(self) -> None:
        if self.tool.official_url.startswith("https://"):
            QDesktopServices.openUrl(QUrl(self.tool.official_url))

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._open()

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            self._open()
            return
        super().keyPressEvent(event)

    def event(self, e: QEvent) -> bool:
        if e.type() in (QEvent.Type.HoverEnter, QEvent.Type.HoverLeave):
            set_prop(self, "hovered", e.type() == QEvent.Type.HoverEnter)
        return super().event(e)


class ModulesScreen(Screen):
    title = "Modules"

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.source_toggle = Segmented([("modules", "Modules"), ("links", "Browser links")])
        self.source_toggle.changed.connect(lambda _k: self._source_changed())
        self.search = SearchField("Search", kbd="Ctrl F")
        self.search.setFixedWidth(240)
        self.search.edit.textChanged.connect(self._filter)
        self.make_header("Modules", "Pick a module to run, or switch to Browser links for sites that open in your browser.",
                         [self.source_toggle, self.search])

        self.legend = QLabel(legend_html(LEGEND))
        self.legend.setTextFormat(Qt.TextFormat.RichText)
        self.legend.setWordWrap(True)
        self.layout_.addWidget(self.legend)

        self.target_filter = self._filter_row(TARGET_FILTERS)
        self.mode_row, self.mode_filter = self._filter_row(MODE_FILTERS, with_host=True)

        self.no_case = Banner("info", "<b>No case open.</b> Modules run inside a case so every result, consent "
                                      "and log is kept with it. Create or open a case first.")
        self.layout_.addWidget(self.no_case)

        self.preset = None
        self.preset_label = label("", "muted")
        self.preset_label.setTextFormat(Qt.TextFormat.RichText)
        clear = button("Show all modules", "ghost", on_click=lambda: self.set_preset(None), name="ClearPreset")
        self.preset_bar = QWidget()
        self.preset_bar.setLayout(hbox(self.preset_label, None, clear, spacing=8))
        self.preset_bar.hide()
        self.layout_.addWidget(self.preset_bar)

        self.grid_host = QWidget()
        self.grid = QGridLayout(self.grid_host)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(12)
        self.cards: dict[str, ModuleCard] = {}
        self.link_cards: dict[str, LinkCard] = {}
        for spec in state.modules:
            card = ModuleCard(spec)
            card.clicked.connect(self.open_module)
            self.cards[spec.id] = card
        self.layout_.addWidget(self.grid_host)
        self.no_match = EmptyState("search", "Nothing matches",
                                   "Try another word or filter, or clear them to see every module and link.",
                                   [button("Clear filters", on_click=self.clear_filters, name="ClearModuleFilters")])
        self.no_match.hide()
        self.layout_.addWidget(self.no_match)
        self.more = label("", "hint", wrap=True)
        self.more.hide()
        self.layout_.addWidget(self.more)
        self.layout_.addStretch(1)
        self._columns = 0
        state.active_case_changed.connect(lambda _c: self.refresh())
        state.catalog_changed.connect(lambda _c: self.refresh())
        state.settings_changed.connect(self.refresh)
        state.target_preset.connect(self.set_preset)
        state.active_case_changed.connect(lambda _c: self.set_preset(None)
                                          if self.preset and (_c is None or _c.id != self.preset.case_id) else None)
        self.refresh()

    def _filter_row(self, options: list[tuple[str, str]], with_host: bool = False):
        group = QButtonGroup(self)
        chips = {key: chip_button(text) for key, text in options}
        row = hbox(spacing=6)
        for chip in chips.values():
            group.addButton(chip)
            row.addWidget(chip)
        row.addStretch(1)
        chips[""].setChecked(True)
        group.buttonClicked.connect(self._filter)
        if with_host:
            host = QWidget()
            host.setLayout(row)
            self.layout_.addWidget(host)
            return host, chips
        self.layout_.addLayout(row)
        return chips

    @property
    def links_mode(self) -> bool:
        return self.source_toggle.current() == "links"

    def _source_changed(self) -> None:
        # The mode filter and the legend are about how modules run; links only ever open a browser.
        self.mode_row.setVisible(not self.links_mode)
        self.legend.setVisible(not self.links_mode)
        self.no_case.setVisible(self.state.active_case is None and not self.links_mode)  # links need no case
        self.search.edit.setPlaceholderText("Search links" if self.links_mode else "Search")
        self._layout_cards(force=True)

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        for spec in self.state.modules:
            status = module_status(spec, self.state.catalog, self.state.db, self.state.keys.has)
            self.cards[spec.id].set_status(status.ready, status.label, status.reason)
        self.no_case.setVisible(self.state.active_case is None and not self.links_mode)
        self._layout_cards(force=True)

    def _filter(self) -> None:
        self._layout_cards(force=True)

    def clear_filters(self) -> None:
        self.search.edit.blockSignals(True)
        self.search.edit.clear()
        self.search.edit.blockSignals(False)
        self.target_filter[""].setChecked(True)
        self.mode_filter[""].setChecked(True)
        self.set_preset(None)  # lays the cards out again

    def focus_search(self) -> None:
        self.search.edit.setFocus()
        self.search.edit.selectAll()

    def set_preset(self, target) -> None:
        """Show only modules that accept this target; clicking one runs it on the target."""
        self.preset = target
        if target is not None:
            mono = theme.tokens()["mono"]
            self.preset_label.setText(
                f'Modules for {target.type.label.lower()} <span style="font-family:\'{mono}\'; '
                f'color:{theme.tokens()["text"]}">{_escape(target.value)}</span>')
        self.preset_bar.setVisible(target is not None)
        self._layout_cards(force=True)

    def visible_ids(self) -> list[str]:
        words = self.search.edit.text().lower().split()
        kind = next(k for k, chip in self.target_filter.items() if chip.isChecked())
        mode = next(k for k, chip in self.mode_filter.items() if chip.isChecked())
        result = []
        for spec in self.state.modules:
            if self.preset is not None and self.preset.type not in spec.target_types:
                continue
            if kind and kind not in {t.value for t in spec.target_types}:
                continue
            tools = [t for t in map(self.state.catalog.get, spec.tools) if t is not None]
            labels = {*spec.labels, *(label.value for tool in tools for label in tool.labels)}  # an engine may be active
            if mode and mode not in labels:
                continue
            text = f"{spec.number} {spec.name} {spec.description} {' '.join(labels)} {' '.join(t.name for t in tools)}".lower()
            if all(w in text for w in words):
                result.append(spec.id)
        return result

    def link_tools(self) -> list[ToolManifest]:
        words = self.search.edit.text().lower().split()
        kind = next(k for k, chip in self.target_filter.items() if chip.isChecked())
        result = []
        for tool in self.state.catalog.tools:
            if tool.launch.kind is not LaunchKind.BROWSER:
                continue
            if self.preset is not None and self.preset.type not in tool.target_types:
                continue
            if kind and kind not in {t.value for t in tool.target_types}:
                continue
            text = f"{tool.name} {tool.description} {tool.category.label}".lower()
            if all(w in text for w in words):
                result.append(tool)
        return result

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._layout_cards()

    def _clear_grid(self) -> None:
        while self.grid.count():
            self.grid.takeAt(0)

    def _columns_for(self, cards) -> int:
        # The widest card (e.g. three tags in a row) sets the column width, so the grid never outgrows the viewport.
        card_w = max([CARD_MIN_WIDTH, *(card.minimumSizeHint().width() for card in cards)])
        width = max(self.viewport().width() - 56, card_w)
        return max(1, (width + 12) // (card_w + 12))

    def _layout_cards(self, force: bool = False) -> None:
        cards = list(self.link_cards.values()) if self.links_mode else list(self.cards.values())
        columns = self._columns_for(cards)
        if columns == self._columns and not force:
            return
        self._columns = columns
        if self.links_mode:
            self._layout_links()
        else:
            self._layout_modules(columns)

    def _place(self, cards: list[QWidget], columns: int) -> None:
        self._clear_grid()
        for col in range(self.grid.columnCount()):
            self.grid.setColumnStretch(col, 0)
        for index, card in enumerate(cards):
            card.show()
            self.grid.addWidget(card, index // columns, index % columns)
        for col in range(columns):
            self.grid.setColumnStretch(col, 1)

    def _layout_modules(self, columns: int) -> None:
        for card in self.link_cards.values():
            card.hide()
        self.more.hide()
        shown = self.visible_ids()
        self.no_match.setVisible(not shown)
        for card in self.cards.values():
            card.setVisible(card.spec.id in shown)
        self._place([self.cards[module_id] for module_id in shown], columns)

    def _layout_links(self) -> None:
        for card in self.cards.values():
            card.hide()
        matches = self.link_tools()
        page = matches[:LINK_MAX]
        shown = {tool.id for tool in page}
        for tool_id in [i for i in self.link_cards if i not in shown]:
            self.link_cards.pop(tool_id).deleteLater()
        cards = [self.link_cards.get(tool.id) or self._make_link_card(tool) for tool in page]
        self._columns = self._columns_for(cards)  # new cards may be wider than the ones measured before
        self._place(cards, self._columns)
        self.no_match.setVisible(not page)
        self.more.setText(f"Showing the first {LINK_MAX} of {len(matches)} links. Use search or the filters to narrow them.")
        self.more.setVisible(len(matches) > LINK_MAX)

    def _make_link_card(self, tool: ToolManifest) -> LinkCard:
        # Parent it right away: polishing ~120 parentless (top-level) cards took 4+ s and froze the window.
        card = LinkCard(tool)
        card.setParent(self.grid_host)
        self.link_cards[tool.id] = card
        return card

    def open_module(self, module_id: str) -> None:
        launch_module(self.window(), self.state, self.state.module(module_id), target=self.preset)
        self.refresh()


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
