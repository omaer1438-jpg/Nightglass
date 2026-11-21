"""Dashboard: quick lookup bar, stats, recent cases (click to open) and activity."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QGridLayout,
    QHeaderView,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from app import formatting, theme
from app.i18n import tr
from app.state import AppState
from app.widgets import (
    Card,
    EmptyState,
    Screen,
    SearchField,
    Segmented,
    StatCard,
    StatusDot,
    button,
    clear_layout,
    hbox,
    label,
    vbox,
)
from core.cases import Case, CaseError
from core.validation import TargetType, ValidationError, detect_type, validate_target

RECENT_LIMIT = 6
LOOKUP_TYPES = [
    ("auto", "Auto"), ("username", "Username"), ("email", "Email"), ("phone", "Phone"),
    ("ip", "IP"), ("domain", "Domain"), ("file", "File"),
]


class DashboardScreen(Screen):
    title = "Dashboard"

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self._show_all = False
        _, self.greeting, self.summary = self.make_header(
            "Good evening",
            " ",
            [
                button("Open modules", icon="mod", on_click=lambda: state.navigate("modules")),
                button("New case", "primary", icon="plus", on_click=lambda: state.navigate("newcase"),
                       name="DashNewCase", tooltip="Create a case (Ctrl+N)"),
            ],
        )

        # Quick lookup (modules arrive later; the bar is here so the layout is final).
        self.lookup_types = Segmented(LOOKUP_TYPES, current="auto")
        self.lookup = SearchField("Username, email, phone, IP, domain or file", kbd="Ctrl K")
        self.analyze = button("Analyze", "primary", on_click=self.analyze_lookup, name="Analyze",
                              tooltip="Add this target to the active case and show the modules that accept it")
        self.lookup.edit.returnPressed.connect(self.analyze_lookup)
        clear = button("Clear", "ghost", on_click=self.lookup.edit.clear)
        lookup_card = Card(padding=(16, 14, 16, 14))
        lookup_card.body_layout.addLayout(hbox(self.lookup_types, self.lookup, self.analyze, clear, spacing=10))
        self.lookup.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.layout_.addWidget(lookup_card)
        self.lookup.edit.setToolTip("Quick lookup (Ctrl+K from any screen)")

        # Stats
        self.stat_open = StatCard("Open cases", "0", " ")
        self.stat_leads = StatCard("Leads to verify", "0", " ", tone="amber")
        self.stat_verified = StatCard("Verified findings", "0", " ", tone="green")
        self.stat_external = StatCard("External lookups (7d)", "0", "all with consent logged")
        stats = QGridLayout()
        stats.setSpacing(14)
        for col, card in enumerate((self.stat_open, self.stat_leads, self.stat_verified, self.stat_external)):
            stats.addWidget(card, 0, col)
            stats.setColumnStretch(col, 1)
        self.layout_.addLayout(stats)

        # Recent cases + activity
        self.view_all = button("View all", "ghost", on_click=self._toggle_all)
        self.recent = Card("Recent cases", right=[self.view_all], padding=(0, 0, 0, 0))
        self.table = _cases_table()
        self.table.cellClicked.connect(self._open_row)
        self.table.cellActivated.connect(self._open_row)
        self.recent_empty = EmptyState(
            "case",
            "No cases yet",
            "Every case starts with a purpose and an authorized scope. Create one to start collecting leads.",
            [button("New case", "primary", icon="plus", on_click=lambda: state.navigate("newcase"))],
        )
        self.recent.body_layout.addWidget(self.table)
        self.recent.body_layout.addWidget(self.recent_empty)

        self.activity_hint = label("", "hint", mono=True)
        self.activity = Card("Activity", right=[self.activity_hint], padding=(16, 6, 16, 10))
        self.activity_list = vbox(spacing=0)
        self.activity.body_layout.addLayout(self.activity_list)
        self.activity.body_layout.addStretch(1)

        lower = QGridLayout()
        lower.setSpacing(14)
        lower.addWidget(self.recent, 0, 0, Qt.AlignmentFlag.AlignTop)
        lower.addWidget(self.activity, 0, 1, Qt.AlignmentFlag.AlignTop)
        lower.setColumnStretch(0, 16)
        lower.setColumnStretch(1, 10)
        self.layout_.addLayout(lower)
        self.layout_.addStretch(1)

        state.cases_changed.connect(self.refresh)
        state.active_case_changed.connect(lambda _case: self.refresh())

    def analyze_lookup(self) -> None:
        """Detect (or use the chosen) type, add the target to the active case, then pick a module."""
        from app.dialogs import Notice

        raw = self.lookup.edit.text().strip()
        if not raw:
            self.lookup.edit.setFocus()
            return
        choice = self.lookup_types.current()
        kind = detect_type(raw) if choice == "auto" else TargetType(choice)
        if kind is None:
            Notice(self.window(), "Which kind of target is this?", [
                "It doesn't look like a username, email, E.164 phone number, IP address, domain or URL.",
                "Pick the type on the left, or check the value.",
            ]).exec()
            return
        try:
            value = validate_target(kind, raw)
        except ValidationError as exc:
            Notice(self.window(), f"That isn't a valid {kind.label.lower()}", [str(exc)]).exec()
            return
        case = self.state.active_case
        if case is None:
            notice = Notice(self.window(), "Open a case first", [
                "Lookups always run inside a case, so every result, consent and log is kept with it.",
            ], action=("New case", None))
            notice.exec()
            if notice.action_taken:
                self.state.navigate("newcase")
            return
        existing = next((t for t in self.state.cases.list_targets(case.id)
                         if t.type is kind and t.value == value), None)
        try:
            target = existing or self.state.cases.add_target(case.id, kind, value, input_source="quick_lookup")
        except CaseError as exc:
            Notice(self.window(), "Can't add this target", [str(exc)]).exec()
            return
        self.state.case_updated(self.state.cases.get_case(case.id))
        self.state.say(f"{kind.label} {value} {'is in' if existing else 'added to'} {case.ref}.")
        self.state.preset_target(target)

    def focus_lookup(self) -> None:
        self.state.navigate("dashboard")
        self.lookup.edit.setFocus()
        self.lookup.edit.selectAll()

    focus_search = focus_lookup  # Ctrl+F on the dashboard

    def on_show(self) -> None:
        self.refresh()

    def _toggle_all(self) -> None:
        self._show_all = not self._show_all
        self.refresh()

    def refresh(self) -> None:
        cases_api = self.state.cases
        stats = cases_api.dashboard_stats()
        self.greeting.setText(tr(formatting.greeting()))
        open_word = "case" if stats.open_cases == 1 else "cases"
        lead_word = "lead" if stats.leads == 1 else "leads"
        self.summary.setText(
            f"{stats.open_cases} open {open_word} · {stats.leads} {lead_word} waiting for verification"
        )
        self.stat_open.set(stats.open_cases, f"{stats.closed_this_week} closed this week")
        across = "case" if stats.cases_with_leads == 1 else "cases"
        self.stat_leads.set(stats.leads, f"across {stats.cases_with_leads} {across}")
        self.stat_verified.set(stats.verified, "confirmed manually")
        self.stat_external.set(stats.external_lookups_7d, "all with consent logged")

        all_cases = cases_api.list_cases()
        shown = all_cases if self._show_all else all_cases[:RECENT_LIMIT]
        self.view_all.setVisible(len(all_cases) > RECENT_LIMIT)
        self.view_all.setText("Show recent" if self._show_all else "View all")
        self._fill_table(shown)
        self.table.setVisible(bool(shown))
        self.recent_empty.setVisible(not shown)

        self._fill_activity(self.state.active_case)

    def _fill_table(self, cases: list[Case]) -> None:
        table = self.table
        for row in range(table.rowCount()):
            old = table.cellWidget(row, 3)
            if old is not None:
                old.hide()
        table.clearContents()
        table.setRowCount(len(cases))
        for row, case in enumerate(cases):
            counts = self.state.cases.counts(case.id)
            dim = not case.is_open
            values = [case.ref, case.name, str(counts.targets), None, formatting.relative(case.updated_at)]
            for col, value in enumerate(values):
                if value is None:
                    continue
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, case.id)
                if col == 0:
                    item.setFont(theme.font("mono", 12))
                if dim:
                    item.setForeground(theme.color("dim"))
                elif col == 4:
                    item.setForeground(theme.color("muted"))
                table.setItem(row, col, item)
            if not case.is_open:
                dot = StatusDot("Closed", "closed")
            elif counts.leads:
                dot = StatusDot(f"{counts.leads} lead{'s' if counts.leads != 1 else ''}", "lead")
            elif counts.verified:
                dot = StatusDot("All verified", "verified")
            else:
                dot = StatusDot("No findings yet", "muted")
            holder = QWidget()
            holder.setLayout(hbox(dot, None))  # the item padding already insets 12px
            holder.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            placeholder = QTableWidgetItem("")
            placeholder.setData(Qt.ItemDataRole.UserRole, case.id)
            table.setItem(row, 3, placeholder)
            table.setCellWidget(row, 3, holder)
        table.setFixedHeight(table.horizontalHeader().height() + 44 * len(cases) + 2)

    def _open_row(self, row: int, _col: int) -> None:
        item = self.table.item(row, 0)
        if item is not None:
            self.state.open_case(item.data(Qt.ItemDataRole.UserRole))

    def _fill_activity(self, case: Case | None) -> None:
        clear_layout(self.activity_list)
        self.activity_hint.setText(case.ref if case else "")
        events = self.state.cases.activity(case.id, limit=6) if case else []
        if not events:
            self.activity_list.addWidget(EmptyState(
                "rev", "No activity yet",
                "Open a case from Recent cases, or create one. Its targets, consents and runs show up here."))
            return
        for index, event in enumerate(events):
            row = QWidget()
            if index < len(events) - 1:
                row.setObjectName("ActivityRow")
                row.setStyleSheet(f"#ActivityRow {{ border-bottom: 1px dashed {theme.tokens()['border']}; }}")
            time_label = label(formatting.clock_time(event.at), "hint", mono=True)
            time_label.setFixedWidth(44)
            detail = f' · <span style="color:{theme.tokens()["muted"]}">{_escape(event.detail)}</span>' if event.detail else ""
            text = label(f"<span>{_escape(event.event)}</span>{detail}", wrap=True)
            text.setStyleSheet("font-size: 12px;")
            row.setLayout(hbox(time_label, text, 1, spacing=12, margins=(0, 9, 0, 9)))
            self.activity_list.addWidget(row)


def _cases_table() -> QTableWidget:
    table = QTableWidget(0, 5)
    table.setHorizontalHeaderLabels(["CASE", "PURPOSE", "TARGETS", "LEADS", "UPDATED"])
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(44)
    table.setShowGrid(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    table.setMouseTracking(True)
    table.setCursor(Qt.CursorShape.PointingHandCursor)
    table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    header = table.horizontalHeader()
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    header.setHighlightSections(False)
    header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
    header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
    for col, width in ((0, 110), (2, 90), (3, 130), (4, 110)):
        table.setColumnWidth(col, width)
    return table


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
