"""Modal dialogs: consent (external / active lookups), target picker, notices."""

from __future__ import annotations

from pathlib import Path

from collections.abc import Sequence

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QLabel,
    QLineEdit,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from app import formatting, icons
from app.i18n import tr
from app.widgets import KeyValueGrid, WrapText, button, hbox, label, tag_row, vbox
from core.findings import StoredFinding
from core.runs import RunRecord, evidence_lines
from core.cases import Case, Target
from core.modules import ALL_ENGINES, Engine, ModuleSpec
from core.validation import TargetType, ValidationError, validate_target


class Modal(QDialog):
    """Frameless rounded dialog in the prototype's .modal style."""

    def __init__(self, parent: QWidget | None, width: int = 540):
        super().__init__(parent)
        self.setObjectName("ModalDialog")
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setModal(True)
        self.frame = QFrame()
        self.frame.setObjectName("Modal")
        self.frame.setFixedWidth(width)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.frame)
        self.body = QVBoxLayout(self.frame)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(0)

    def exec(self) -> int:
        # Dim the window behind the dialog (prototype .scrim) while it is open.
        host = self.parentWidget().window() if self.parentWidget() is not None else None
        scrim = None
        if host is not None and host.isVisible():
            scrim = QWidget(host)
            scrim.setObjectName("ModalScrim")
            scrim.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
            scrim.setGeometry(host.rect())
            scrim.show()
            scrim.raise_()
        try:
            result = super().exec()
        finally:
            if scrim is not None:
                scrim.hide()
                scrim.deleteLater()
        QTimer.singleShot(0, self.deleteLater)  # callers still read the dialog right after this returns
        return result

    def header(self, icon_name: str, tone: str, title: str, sub: str) -> QLabel:
        glyph = QLabel()
        glyph.setObjectName(f"ModalIcon_{tone}")
        glyph.setFixedSize(36, 36)
        glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        glyph.setPixmap(icons.pixmap(icon_name, tone, 18))
        title_label = label(tr(title), "h2")
        title_label.setStyleSheet("font-size: 15px;")
        title_label.setWordWrap(True)
        self.sub = label(sub, "sub", wrap=True)
        row = hbox(glyph, spacing=12, margins=(20, 18, 20, 6))
        row.addLayout(vbox(title_label, self.sub, spacing=4), 1)
        row.setAlignment(glyph, Qt.AlignmentFlag.AlignTop)
        self.body.addLayout(row)
        return title_label

    def content(self) -> QVBoxLayout:
        layout = vbox(spacing=8, margins=(20, 8, 20, 16))
        self.body.addLayout(layout)
        return layout

    def footer(self, *widgets) -> None:
        foot = QFrame()
        foot.setProperty("cardFoot", True)
        foot.setLayout(hbox(*widgets, spacing=8, margins=(20, 14, 20, 14)))
        self.body.addWidget(foot)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
            return
        super().keyPressEvent(event)


class ConsentDialog(Modal):
    """Shows exactly which data goes to which provider before an external or active lookup."""

    def __init__(self, parent, spec: ModuleSpec, case: Case, target: Target, consent_ref: str,
                 engine: Engine | None = None):
        super().__init__(parent)
        labels = engine.labels if engine else spec.labels
        provider = engine.provider if engine else spec.provider
        self.active = engine.is_active if engine else spec.is_active
        name = f"{spec.name} ({engine.name})" if engine and engine.tool else spec.name
        if self.active:
            self.header("warn", "red", "Active check: this touches the target's systems",
                        f"{name} contacts the target or third-party account flows directly. Only run it "
                        "against targets you own or are authorized to test.")
        else:
            self.header("warn", "amber", "This lookup sends data outside your computer",
                        f"{name} will query an external provider.")
        body = self.content()
        kv = KeyValueGrid()
        tags = [t for t in labels if t != "oss"]
        kv.set_rows([
            ("Module", spec.title + (f" · {engine.name}" if engine and engine.tool else "")),
            ("Data sent", label(target.value, mono=True, selectable=True)),
            ("Sent to", provider),
            ("Mode", tag_row(tags)),
            ("Case scope", case.authorized_scope),
        ])
        body.addWidget(kv)
        self.scope_box = QCheckBox(f"This lookup is within the authorized scope of {case.ref}.")
        self.owner_box = QCheckBox(tr("I own this target or have written authorization to test it."))
        self.remember_box = QCheckBox(tr("Don't ask again for this module in this case."))
        body.addWidget(self.scope_box)
        if self.active:
            body.addWidget(self.owner_box)
        else:
            body.addWidget(self.remember_box)
        for box in (self.scope_box, self.owner_box):
            box.toggled.connect(self._update)

        self.ok = button("Run active check" if self.active else "Send and run",
                         "danger" if self.active else "primary", on_click=self.accept, name="ConsentOk")
        self.ok.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        cancel = button("Cancel", "ghost", on_click=self.reject, name="ConsentCancel")
        cancel.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.footer(label(f"Consent will be logged as {consent_ref}", "hint"), None, cancel, self.ok)
        self._update()
        cancel.setFocus()

    def _update(self) -> None:
        ready = self.scope_box.isChecked() and (not self.active or self.owner_box.isChecked())
        self.ok.setEnabled(ready)

    @property
    def remember(self) -> bool:
        return not self.active and self.remember_box.isChecked()


class TargetPicker(Modal):
    """Pick one of the case's targets for a module, or add a new one."""

    def __init__(self, parent, spec: ModuleSpec, case: Case, targets: Sequence[Target], preset: str = "",
                 engines: Sequence[Engine] = (), fixed_target: Target | None = None):
        super().__init__(parent, width=520)
        self.spec, self.case = spec, case
        self.fixed_target = fixed_target
        self.engine_id: str | None = None
        accepted = ", ".join(t.label.lower() for t in spec.target_types)
        self.header(spec.icon, "accent", f"Run {spec.title}", f"{spec.description} Accepts: {accepted}.")
        body = self.content()
        self.engine_box = QComboBox()
        for engine in engines:
            tags = ", ".join(t for t in engine.labels if t != "oss")
            self.engine_box.addItem(f"{engine.name}  ({tags})", engine.id)
        if len(engines) > 1:
            self.engine_box.addItem(f"All {len(engines)} tools, one after another", ALL_ENGINES)
            body.addWidget(label("Run with", "field"))
            body.addWidget(self.engine_box)
        self.group = QButtonGroup(self)
        self.choices: dict[int, Target] = {}
        matching = [t for t in targets if t.type in spec.target_types]
        if fixed_target is not None:
            matching = []
            body.addWidget(label(f"Target: {fixed_target.type.label} · {fixed_target.value}", "muted"))
        if matching:
            body.addWidget(label(f"Targets in {case.ref}", "field"))
            for index, target in enumerate(matching):
                radio = QRadioButton(f"{target.type.label} · {target.value}")
                radio.setProperty("mono", True)
                self.group.addButton(radio, index)
                self.choices[index] = target
                body.addWidget(radio)
            self.group.buttons()[0].setChecked(True)
        self.new_radio = QRadioButton("New target")
        self.group.addButton(self.new_radio, -2)
        self.type_box = QComboBox()
        for kind in spec.target_types:
            self.type_box.addItem(kind.label, kind)
        self.type_box.setVisible(len(spec.target_types) > 1)
        self.value = QLineEdit(preset)
        self.value.setPlaceholderText({
            TargetType.USERNAME: "example_user", TargetType.EMAIL: "name@example.com",
            TargetType.PHONE: "+1 555 010 0123", TargetType.IP: "192.0.2.10",
            TargetType.DOMAIN: "example.com", TargetType.URL: "https://example.com",
            TargetType.FILE: "Full path to a local file",
        }.get(spec.target_types[0], ""))
        self.value.textEdited.connect(lambda: self.new_radio.setChecked(True))
        self.error = label("", "error", wrap=True)
        self.error.hide()
        if fixed_target is None:
            body.addWidget(self.new_radio)
            row = hbox(self.type_box, self.value, spacing=8)
            if TargetType.FILE in spec.target_types:
                row.addWidget(button("Browse…", icon="folder", on_click=self._browse))
            body.addLayout(row)
        else:
            for widget in (self.new_radio, self.type_box, self.value):
                widget.hide()
        body.addWidget(self.error)
        if not matching or preset:
            self.new_radio.setChecked(True)
        self.ok = button("Continue", "primary", on_click=self._accept, name="PickerOk")
        self.ok.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.footer(None, button("Cancel", "ghost", on_click=self.reject), self.ok)
        self.selected: Target | None = None
        self.new_target: tuple[TargetType, str] | None = None

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file", "", "All files (*.*)")
        if path:
            self.value.setText(path)
            self.new_radio.setChecked(True)

    def _accept(self) -> None:
        self.engine_id = self.engine_box.currentData()
        if self.fixed_target is not None:
            self.accept()
            return
        if self.new_radio.isChecked():
            kind: TargetType = self.type_box.currentData()
            try:
                value = validate_target(kind, self.value.text())
            except ValidationError as exc:
                self.error.setText(str(exc))
                self.error.show()
                return
            self.new_target = (kind, value)
        else:
            self.selected = self.choices[self.group.checkedId()]
        self.accept()


class EvidenceDialog(Modal):
    """What a finding rests on: where it came from, and the raw lines the tool printed."""

    def __init__(self, parent, finding: StoredFinding, run: RunRecord | None):
        super().__init__(parent, width=640)
        self.finding, self.run = finding, run
        self.header("search", "accent", finding.title,
                    f"{finding.source} · {formatting.long_datetime(finding.collected_at)}"
                    + (f" · run r-{run.id:04d}" if run else ""))
        body = self.content()

        def section(title: str, text: str, tone: str = "muted") -> WrapText:
            box = WrapText(mono=True, tone=tone)
            box.setPlainText(text)
            body.addWidget(label(title, "field"))
            body.addWidget(box)
            return box

        if finding.url:
            section("Source link", finding.url, "accent")
        if finding.value and finding.value != finding.url:
            section("Result", finding.value, "text")
        log_path = Path(run.log_path) if run and run.log_path else None
        lines = evidence_lines(log_path, finding) if log_path else []
        fallback = f"No matching line in the log. This result came from {finding.raw_ref or 'the module itself'}."
        self.raw = section("Raw tool output", "\n".join(lines) or fallback)
        body.addWidget(label("Evidence shows where a result came from. It does not prove who owns an account.", "hint", wrap=True))
        widgets = [None, button("Close", "ghost", on_click=self.reject, name="EvidenceClose")]
        if log_path and log_path.is_file():
            widgets.insert(0, button("Open run log", on_click=lambda: _open(QUrl.fromLocalFile(str(log_path)))))
        if (finding.url or "").startswith(("https://", "http://")):
            widgets.insert(0, button("Open source link", "primary", on_click=lambda: _open(QUrl(finding.url))))
        self.footer(*widgets)


def _open(url: QUrl) -> None:
    QDesktopServices.openUrl(url)


class EvidenceLinkDialog(Modal):
    """Before adding an evidence file: optionally link it to one of the case's findings."""

    def __init__(self, parent, file_name: str, case: Case, findings: Sequence[StoredFinding],
                 selected_id: int | None = None):
        super().__init__(parent, width=480)
        self.header("clip", "accent", "Add evidence",
                    f"{file_name} will be copied into the evidence folder of {case.ref} and its SHA-256 recorded.")
        body = self.content()
        body.addWidget(label("Linked finding", "field"))
        self.finding_box = QComboBox()
        self.finding_box.addItem(tr("None (evidence for the whole case)"), None)
        for finding in findings:
            self.finding_box.addItem(f"{finding.title} · {finding.source}", finding.id)
        self.finding_box.setCurrentIndex(max(0, self.finding_box.findData(selected_id)))
        body.addWidget(self.finding_box)
        body.addWidget(label("Linking shows what a finding rests on. It doesn't verify the finding.", "hint", wrap=True))
        ok = button("Add evidence", "primary", on_click=self.accept, name="EvidenceLinkOk")
        ok.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.footer(None, button("Cancel", "ghost", on_click=self.reject), ok)

    @property
    def finding_id(self) -> int | None:
        return self.finding_box.currentData()


class DeleteCaseDialog(Modal):
    """Named destructive confirmation: type the case ref to enable Delete."""

    def __init__(self, parent, case: Case):
        super().__init__(parent, width=480)
        self.header("warn", "red", f"Delete {case.ref} permanently?",
                    f"\u201c{case.name}\u201d, its targets, findings, runs, consents, evidence files, reports "
                    "and logs will be removed from this computer. This can't be undone.")
        body = self.content()
        body.addWidget(label(f"Type {case.ref} to confirm", "field"))
        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText(case.ref)
        body.addWidget(self.confirm)
        self.ok = button("Delete case", "danger", on_click=self.accept, name="ConfirmDelete")
        self.ok.setEnabled(False)
        self.confirm.textChanged.connect(lambda text: self.ok.setEnabled(text.strip().upper() == case.ref))
        cancel = button("Cancel", "ghost", on_click=self.reject)
        self.footer(None, cancel, self.ok)
        self.confirm.setFocus()


class Notice(Modal):
    def __init__(self, parent, title: str, lines: Sequence[str], tone: str = "amber",
                 action: tuple[str, object] | None = None):
        super().__init__(parent, width=480)
        self.header("warn" if tone != "accent" else "info", tone, title, "")
        self.sub.hide()
        body = self.content()
        for line in lines:
            body.addWidget(label(f"•  {line}", wrap=True))
        widgets: list = [None]
        self.action_taken = False
        if action:
            text, _ = action
            widgets.append(button(text, on_click=self._take))
        close = button("Close", "primary", on_click=self.accept)
        close.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        widgets.append(close)
        self.footer(*widgets)

    def _take(self) -> None:
        self.action_taken = True
        self.accept()
