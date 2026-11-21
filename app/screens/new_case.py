"""New case: purpose, authorized scope, allowed modes and an optional first target."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFrame,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QWidget,
)

from app import formatting, icons
from app.i18n import tr
from app.state import AppState
from app.widgets import (
    Banner,
    Card,
    KeyValueGrid,
    ResponsiveColumns,
    Screen,
    button,
    hbox,
    label,
    set_prop,
    tag_row,
    vbox,
)
from core.cases import LookupMode, NewCase, NewCaseInvalid
from core.validation import TargetType, ValidationError, validate_target

MODE_CHIPS = [
    (LookupMode.LOCAL, "Local"),
    (LookupMode.EXTERNAL_PASSIVE, "External · passive"),
    (LookupMode.ACTIVE, "Active (requires authorization)"),
]
MODE_TAGS = {
    LookupMode.LOCAL: ["local"],
    LookupMode.EXTERNAL_PASSIVE: ["external", "passive"],
    LookupMode.ACTIVE: ["active"],
}
TYPE_CHIPS = [
    (TargetType.USERNAME, "user"),
    (TargetType.EMAIL, "mail"),
    (TargetType.PHONE, "phone"),
    (TargetType.IP, "pin"),
    (TargetType.DOMAIN, "globe"),
    (TargetType.URL, "ext"),
    (TargetType.FILE, "img"),
    (TargetType.OTHER, "head"),
]
PLACEHOLDERS = {
    TargetType.USERNAME: "example_user",
    TargetType.EMAIL: "name@example.com",
    TargetType.PHONE: "+1 555 010 0123 (E.164, with country code)",
    TargetType.IP: "192.0.2.10",
    TargetType.DOMAIN: "example.com",
    TargetType.URL: "https://example.com/page",
    TargetType.FILE: "Choose a file on this computer",
    TargetType.OTHER: "Short description",
}
STEPS = ["Details", "Scope", "Targets", "Review"]


class Field(QWidget):
    """Label, input, inline error and optional hint (.field in the prototype)."""

    def __init__(self, title: str, widget: QWidget, hint: str = "", body: QWidget | None = None):
        super().__init__()
        self.input = widget
        self.error = label("", "error", wrap=True)
        self.error.hide()
        title_label = label(tr(title), "field")
        title_label.setBuddy(widget)
        items: list = [title_label, body or widget, self.error]
        if hint:
            items.append(label(hint, "hint", wrap=True))
        self.setLayout(vbox(*items, spacing=6))

    def set_error(self, message: str | None) -> None:
        self.error.setText(message or "")
        self.error.setVisible(bool(message))
        set_prop(self.input, "invalid", bool(message))


class Step(QFrame):
    def __init__(self, number: int, text: str):
        super().__init__()
        self.number = number
        self.badge = QLabel(str(number))
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.text = QLabel(tr(text))
        self.setLayout(hbox(self.badge, self.text, None, spacing=9, margins=(12, 9, 12, 9)))
        self.set_state("idle")

    def set_state(self, state: str) -> None:
        self.badge.setText("✓" if state == "done" else str(self.number))
        set_prop(self, "step", state)
        set_prop(self.badge, "stepnum", state)
        set_prop(self.text, "steptext", state)


def _text_area(placeholder: str, min_height: int = 72) -> QPlainTextEdit:
    widget = QPlainTextEdit()
    widget.setPlaceholderText(placeholder)
    widget.setTabChangesFocus(True)
    widget.setFixedHeight(min_height)
    return widget


class NewCaseScreen(Screen):
    title = "New Case"

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.make_header("New case", "Every case starts with a purpose and an authorized scope.")

        self.steps = [Step(i + 1, text) for i, text in enumerate(STEPS)]
        self.layout_.addLayout(hbox(*self.steps, spacing=8))
        self.layout_.addSpacing(6)

        # ---- form
        self.name = QLineEdit()
        self.name.setPlaceholderText("Account impersonation review")
        self.name.setMaxLength(120)
        self.purpose = _text_area("Why does this case exist? What question should it answer?")
        self.scope = _text_area("What you are authorized to look at: your own accounts, domains, assets…")

        self.f_name = Field("Case name", self.name)
        self.f_purpose = Field("Purpose", self.purpose)
        self.f_scope = Field(
            "Authorized scope", self.scope, hint="Active modules will check this scope before they can run."
        )

        self.mode_buttons: dict[LookupMode, QPushButton] = {}
        chips = hbox(spacing=6)
        for mode, text in MODE_CHIPS:
            chip = QPushButton(tr(text))
            chip.setProperty("chip", True)
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.setFocusPolicy(Qt.FocusPolicy.TabFocus)
            if mode is LookupMode.ACTIVE:
                chip.setProperty("danger", True)
            chip.toggled.connect(self._changed)
            self.mode_buttons[mode] = chip
            chips.addWidget(chip)
        chips.addStretch(1)
        modes_holder = QWidget()
        modes_holder.setLayout(chips)
        self.active_note = label(
            "Active modules also stay off until you enable them in Settings, and each run is "
            "checked against this scope.",
            "hint",
            tone="red",
            wrap=True,
        )
        self.f_modes = Field("Allowed lookup modes", modes_holder)
        self.f_modes.layout().addWidget(self.active_note)

        self.type_group = QButtonGroup(self)
        self.type_group.setExclusive(True)
        self.type_buttons: dict[TargetType, QPushButton] = {}
        grid = QGridLayout()
        grid.setSpacing(8)
        for index, (kind, icon_name) in enumerate(TYPE_CHIPS):
            chip = QPushButton(tr(kind.label))
            chip.setProperty("typechip", True)
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.setFocusPolicy(Qt.FocusPolicy.TabFocus)
            chip.setIcon(icons.icon(icon_name, "muted", on_token="text", size=16))
            chip.setIconSize(QSize(16, 16))
            chip.clicked.connect(lambda _=False, k=kind: self._type_picked(k))
            self.type_group.addButton(chip)
            self.type_buttons[kind] = chip
            grid.addWidget(chip, index // 4, index % 4)
        self.target_value = QLineEdit()
        self.target_value.editingFinished.connect(self._validate_target_on_blur)
        self.browse = button("Browse…", icon="folder", on_click=self._browse)
        target_body = QWidget()
        target_body.setLayout(vbox(grid, hbox(self.target_value, self.browse, spacing=8), spacing=10))
        self.f_target = Field(
            "First target", self.target_value, hint="Optional. You can add more targets later.", body=target_body
        )

        form = Card(padding=(16, 16, 16, 6))
        for field in (self.f_name, self.f_purpose, self.f_scope, self.f_modes, self.f_target):
            form.body_layout.addWidget(field)
            form.body_layout.addSpacing(4)
        footer = QFrame()
        footer.setProperty("cardFoot", True)
        self.create_btn = button("Create case", "primary", on_click=self.create_case, name="CreateCase")
        footer.setLayout(
            hbox(button("Back", "ghost", on_click=lambda: state.navigate("dashboard")), None, self.create_btn,
                 margins=(16, 14, 16, 14))
        )
        form.layout().addWidget(footer)

        # ---- side column
        self.summary = KeyValueGrid()
        summary_card = Card("Case summary")
        summary_card.body_layout.addWidget(self.summary)
        side = vbox(
            Banner("info", "<b>Stored locally.</b> Case data stays in your local cases folder. "
                           "Nothing is synced or uploaded."),
            Banner("warn", "Results are <b>leads</b>, not proof of identity. A username match does not "
                           "prove who owns an account."),
            summary_card,
            None,
            spacing=14,
        )
        side_host = QWidget()
        side_host.setLayout(side)
        self.columns = ResponsiveColumns(form, side_host, breakpoint=1000, side_width=440)
        self.layout_.addWidget(self.columns)
        self.layout_.addStretch(1)

        for widget in (self.name, self.purpose, self.scope):
            widget.textChanged.connect(self._changed)
        self.name.textChanged.connect(lambda: self.f_name.set_error(None))
        self.purpose.textChanged.connect(lambda: self.f_purpose.set_error(None))
        self.scope.textChanged.connect(lambda: self.f_scope.set_error(None))
        self.target_value.textChanged.connect(lambda: self.f_target.set_error(None))
        self.target_value.textChanged.connect(self._changed)

        self.reset()

    # ---- state

    def reset(self) -> None:
        self.name.clear()
        self.purpose.clear()
        self.scope.clear()
        for mode, chip in self.mode_buttons.items():
            chip.setChecked(mode in (LookupMode.LOCAL, LookupMode.EXTERNAL_PASSIVE))
        self._type_picked(TargetType.USERNAME)
        self.target_value.clear()
        for field in (self.f_name, self.f_purpose, self.f_scope, self.f_modes, self.f_target):
            field.set_error(None)
        self._changed()

    def on_show(self) -> None:
        for field in (self.f_name, self.f_purpose, self.f_scope, self.f_modes, self.f_target):
            field.set_error(None)  # errors belong to the last submit, not to a new visit
        self._changed()
        self.name.setFocus()

    def selected_modes(self) -> list[LookupMode]:
        return [mode for mode, chip in self.mode_buttons.items() if chip.isChecked()]

    def selected_type(self) -> TargetType:
        return next(kind for kind, chip in self.type_buttons.items() if chip.isChecked())

    def _type_picked(self, kind: TargetType) -> None:
        self.type_buttons[kind].setChecked(True)
        self.target_value.setPlaceholderText(PLACEHOLDERS[kind])
        self.browse.setVisible(kind is TargetType.FILE)
        self.f_target.set_error(None)
        self._changed()

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file", "", "All files (*.*)")
        if path:
            self.target_value.setText(path)

    def _target_error(self) -> str | None:
        value = self.target_value.text()
        if not value.strip():
            return None
        try:
            validate_target(self.selected_type(), value)
        except ValidationError as exc:
            return str(exc)
        return None

    def _validate_target_on_blur(self) -> None:
        self.f_target.set_error(self._target_error())

    def _changed(self, *_args) -> None:
        details = bool(self.name.text().strip() and self.purpose.toPlainText().strip())
        scope = bool(self.scope.toPlainText().strip() and self.selected_modes())
        target = bool(self.target_value.text().strip()) and self._target_error() is None
        done = [details, scope, target]
        current = next((i for i, ok in enumerate(done) if not ok), 3)
        for index, step in enumerate(self.steps):
            if index == current:
                step.set_state("on")
            elif index < 3 and done[index]:
                step.set_state("done")
            else:
                step.set_state("idle")
        self.active_note.setVisible(self.mode_buttons[LookupMode.ACTIVE].isChecked())
        if self.selected_modes():
            self.f_modes.set_error(None)
        self._refresh_summary()

    def _refresh_summary(self) -> None:
        tags = [t for mode in self.selected_modes() for t in MODE_TAGS[mode]]
        modes = tag_row(tags) if tags else label("None selected", "muted")
        value = self.target_value.text().strip()
        if value and self._target_error() is None:
            first_target = f"{self.selected_type().label} · {validate_target(self.selected_type(), value)}"
        else:
            first_target = "None yet"
        retention = self.state.db.get_setting("retention_days", 90)
        ref = label(self.state.cases.next_case_ref(), mono=True)
        self.summary.set_rows(
            [
                ("ID", ref),
                ("Created", formatting.long_datetime(datetime.now().astimezone())),
                ("Modes", modes),
                ("First target", first_target),
                ("Retention", f"Delete {retention} days after closing" if retention else "Keep until deleted"),
            ]
        )

    # ---- create

    def create_case(self) -> None:
        new = NewCase(
            name=self.name.text(),
            purpose=self.purpose.toPlainText(),
            authorized_scope=self.scope.toPlainText(),
            allowed_modes=self.selected_modes(),
            first_target_type=self.selected_type(),
            first_target_value=self.target_value.text(),
        )
        try:
            case = self.state.cases.create_case(new)
        except NewCaseInvalid as exc:
            fields = {
                "name": self.f_name,
                "purpose": self.f_purpose,
                "authorized_scope": self.f_scope,
                "allowed_modes": self.f_modes,
                "first_target": self.f_target,
            }
            for key, field in fields.items():
                field.set_error(exc.errors.get(key))
            first = next(fields[k] for k in fields if k in exc.errors)
            first.input.setFocus()
            self.ensureWidgetVisible(first)
            return
        self.reset()
        self.state.cases_changed.emit()
        self.state.open_case(case.id)
        self.state.say(f"{case.ref} created and saved locally.")
