"""Reusable components matching the prototype (buttons, cards, tags, tabs, nav)."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from PySide6.QtCore import QEvent, QObject, QPoint, QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QTextOption, QFontMetrics, QPainter, QPaintEvent
from PySide6.QtWidgets import (
    QAbstractButton,
    QButtonGroup,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from app import icons, theme
from app.i18n import tr, tr_status

# ---------------------------------------------------------------- helpers


def repolish(widget: QWidget) -> None:
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def set_prop(widget: QWidget, name: str, value) -> None:
    if widget.property(name) != value:
        widget.setProperty(name, value)
        repolish(widget)


def clear_layout(layout: QLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            # Hide now: deleteLater() only runs when the event loop gets back control.
            item.widget().hide()
            item.widget().deleteLater()
        elif item.layout():
            clear_layout(item.layout())


def hbox(*items, spacing: int = 8, margins=(0, 0, 0, 0)) -> QHBoxLayout:
    layout = QHBoxLayout()
    layout.setSpacing(spacing)
    layout.setContentsMargins(*margins)
    for item in items:
        _add(layout, item)
    return layout


def vbox(*items, spacing: int = 8, margins=(0, 0, 0, 0)) -> QVBoxLayout:
    layout = QVBoxLayout()
    layout.setSpacing(spacing)
    layout.setContentsMargins(*margins)
    for item in items:
        _add(layout, item)
    return layout


def _add(layout, item) -> None:
    if item is None:
        layout.addStretch(1)
    elif isinstance(item, QLayout):
        layout.addLayout(item)
    elif isinstance(item, int):
        layout.addSpacing(item)
    else:
        layout.addWidget(item)


def label(
    text: str = "",
    role: str | None = None,
    *,
    tone: str | None = None,
    mono: bool = False,
    wrap: bool = False,
    selectable: bool = False,
    name: str | None = None,
) -> QLabel:
    widget = QLabel(tr(text))
    if role:
        widget.setProperty("role", role)
    if tone:
        widget.setProperty("tone", tone)
    if mono:
        widget.setProperty("mono", True)
    if wrap:
        widget.setWordWrap(True)
    if selectable:
        widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if name:
        widget.setObjectName(name)
    widget.setTextFormat(Qt.TextFormat.PlainText if not text.startswith("<") else Qt.TextFormat.RichText)
    return widget


_ICON_TOKEN_FOR_VARIANT = {"primary": "accent-ink", "ghost": "muted", "danger": "red"}


def button(
    text: str,
    variant: str | None = None,
    *,
    icon: str | None = None,
    on_click: Callable[[], None] | None = None,
    tooltip: str | None = None,
    name: str | None = None,
) -> QPushButton:
    widget = QPushButton(tr(text))
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    widget.setFocusPolicy(Qt.FocusPolicy.TabFocus)  # focus ring for keyboard users only
    if variant:
        widget.setProperty("variant", variant)
    if icon:
        widget.setIcon(icons.icon(icon, _ICON_TOKEN_FOR_VARIANT.get(variant, "text"), on_token=None, size=14))
        widget.setIconSize(QSize(14, 14))
    if on_click:
        widget.clicked.connect(on_click)
    if tooltip:
        widget.setToolTip(tooltip)
    if name:
        widget.setObjectName(name)
    return widget


TAG_TEXT = {
    "local": "Local",
    "external": "External",
    "passive": "Passive",
    "active": "Active",
    "api_key": "API key",
    "oss": "Open source",
}


def tag(kind: str, text: str | None = None) -> QLabel:
    widget = QLabel(tr(text or TAG_TEXT[kind]).upper())
    widget.setProperty("tag", kind)
    f = widget.font()
    f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.5)
    widget.setFont(f)
    widget.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    return widget


def tag_row(kinds: Iterable[str]) -> QWidget:
    holder = QWidget()
    layout = hbox(*[tag(k) for k in kinds], None, spacing=4)
    holder.setLayout(layout)
    return holder


# ---------------------------------------------------------------- cards


class Card(QFrame):
    """Surface with a 1px border and 10px radius; optional header row."""

    def __init__(self, title: str | None = None, right: Sequence[QWidget] = (), padding=(16, 14, 16, 14),
                 icon: tuple[str, str] | None = None):
        super().__init__()
        self.setProperty("card", True)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.head: QFrame | None = None
        if title is not None:
            self.head = QFrame()
            self.head.setProperty("cardHead", True)
            self.title_label = label(tr(title), "h2")
            row = hbox(self.title_label, None, *right, spacing=10, margins=(16, 11, 16, 11))
            if icon:  # (icon name, color token), e.g. ("shield", "accent")
                glyph = QLabel()
                glyph.setPixmap(icons.pixmap(icon[0], icon[1], 16))
                row.insertWidget(0, glyph)
            self.head.setLayout(row)
            self.head.setMinimumHeight(46)
            outer.addWidget(self.head)
        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(*padding)
        self.body_layout.setSpacing(10)
        outer.addWidget(self.body, 1)


class StatCard(Card):
    def __init__(self, key: str, value: str = "0", detail: str = "", tone: str | None = None):
        super().__init__(padding=(16, 14, 16, 14))
        self.body_layout.setSpacing(2)
        self.key = label(tr(key), "stat-k")
        self.value = label(value, "stat-v", tone=tone)
        self.detail = label(detail, "stat-d")
        self.body_layout.addWidget(self.key)
        self.body_layout.addSpacing(4)
        self.body_layout.addWidget(self.value)
        self.body_layout.addWidget(self.detail)
        self.detail.setVisible(bool(detail))

    def set(self, value: int | str, detail: str | None = None) -> None:
        self.value.setText(str(value))
        if detail is not None:
            self.detail.setText(detail)
            self.detail.setVisible(bool(detail))


class Banner(QFrame):
    _ICON = {"info": ("info", "accent"), "warn": ("warn", "amber"), "danger": ("warn", "red")}

    def __init__(self, kind: str, html: str):
        super().__init__()
        self.setProperty("banner", kind)
        name, token = self._ICON[kind]
        glyph = QLabel()
        glyph.setPixmap(icons.pixmap(name, token, 16))
        glyph.setFixedSize(16, 18)
        glyph.setAlignment(Qt.AlignmentFlag.AlignBottom)
        self.text = QLabel(tr(html))
        self.text.setTextFormat(Qt.TextFormat.RichText)
        self.text.setWordWrap(True)
        row = hbox(spacing=10, margins=(13, 10, 13, 10))
        row.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
        row.addWidget(self.text, 1)
        self.setLayout(row)


class KeyValueGrid(QFrame):
    def __init__(self, framed: bool = True):
        super().__init__()
        if framed:
            self.setProperty("kv", True)
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(*((14, 12, 14, 12) if framed else (0, 0, 0, 0)))
        self.grid.setHorizontalSpacing(12)
        self.grid.setVerticalSpacing(8)
        self.grid.setColumnMinimumWidth(0, 120)
        self.grid.setColumnStretch(1, 1)

    def set_rows(self, rows: Sequence[tuple[str, QWidget | str]]) -> None:
        clear_layout(self.grid)
        for index, (key, value) in enumerate(rows):
            key_label = label(key, "muted")
            key_label.setStyleSheet("font-size: 12px;")
            widget = value if isinstance(value, QWidget) else label(value, wrap=True, selectable=True)
            if isinstance(widget, QLabel) and not widget.property("mono"):
                widget.setStyleSheet("font-size: 12px;")
            self.grid.addWidget(key_label, index, 0, Qt.AlignmentFlag.AlignTop)
            self.grid.addWidget(widget, index, 1)


class StatusDot(QWidget):
    """Colored 6px dot + label (Lead / Verified / Rejected / Uncertain / Closed)."""

    TONES = {
        "lead": "amber",
        "verified": "green",
        "rejected": "dim",
        "uncertain": "blue",
        "open": "green",
        "closed": "dim",
        "muted": "muted",
    }

    def __init__(self, text: str, kind: str, pixel_size: int = 12):
        super().__init__()
        self._font = theme.font("sans", pixel_size)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        self.set(text, kind)

    def set(self, text: str, kind: str) -> None:
        self._source_text = text
        text = tr_status(text)
        self._text = text
        self._color = theme.color(self.TONES.get(kind, kind))
        self.setAccessibleName(text)
        self.updateGeometry()
        self.update()

    def text(self) -> str:
        return self._source_text

    def sizeHint(self) -> QSize:
        metrics = QFontMetrics(self._font)
        return QSize(12 + metrics.horizontalAdvance(self._text) + 2, max(18, metrics.height()))

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        cy = self.height() / 2
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._color)
        painter.drawEllipse(QRectF(self.width() - 6 if rtl else 0, cy - 3, 6, 6))
        painter.setPen(self._color)
        painter.setFont(self._font)
        text_rect = QRect(0, 0, self.width() - 12, self.height()) if rtl else QRect(12, 0, self.width() - 12, self.height())
        align = Qt.AlignmentFlag.AlignVCenter | (Qt.AlignmentFlag.AlignRight if rtl else Qt.AlignmentFlag.AlignLeft)
        painter.drawText(text_rect, align, self._text)


class EmptyState(QWidget):
    def __init__(self, icon_name: str, title: str, text: str, actions: Sequence[QPushButton] = ()):
        super().__init__()
        glyph = QLabel()
        glyph.setPixmap(icons.pixmap(icon_name, "dim", 28))
        glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading = label(tr(title), "empty-title")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body = label(text, "muted", wrap=True)
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body.setMaximumWidth(460)
        # Centre via stretches, not setAlignment: an aligned label gets its one-line sizeHint, not its wrapped height.
        row = hbox(None, spacing=0)
        row.addWidget(body, 100)  # takes the width up to its 460 cap; the stretches share the rest
        row.addStretch(1)
        layout = vbox(glyph, 4, heading, row, spacing=6, margins=(24, 36, 24, 36))
        if actions:
            row = hbox(None, *actions, None, spacing=8)
            layout.addSpacing(10)
            layout.addLayout(row)
        self.setLayout(layout)


# ---------------------------------------------------------------- inputs


class _FocusWatcher(QObject):
    def __init__(self, frame: QFrame):
        super().__init__(frame)
        self._frame = frame

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() in (QEvent.Type.FocusIn, QEvent.Type.FocusOut):
            set_prop(self._frame, "focused", event.type() == QEvent.Type.FocusIn)
        return False


class SearchField(QFrame):
    """36px input with a leading search icon and an optional kbd hint."""

    def __init__(self, placeholder: str = "", kbd: str | None = None, icon_name: str = "search"):
        super().__init__()
        self.setProperty("input", True)
        self.setFixedHeight(36)
        glyph = QLabel()
        glyph.setPixmap(icons.pixmap(icon_name, "dim", 15))
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        self.edit.installEventFilter(_FocusWatcher(self))
        items: list = [glyph, self.edit]
        if kbd:
            hint = QLabel(kbd)
            hint.setProperty("kbd", True)
            items.append(hint)
        self.setLayout(hbox(*items, spacing=8, margins=(10, 0, 10, 0)))
        self.setCursor(Qt.CursorShape.IBeamCursor)

    def mousePressEvent(self, event) -> None:
        self.edit.setFocus()
        super().mousePressEvent(event)


class Segmented(QFrame):
    """Segmented control: exclusive buttons in a rounded track."""

    changed = Signal(str)

    def __init__(self, options: Sequence[tuple[str, str]], current: str | None = None):
        super().__init__()
        self.setProperty("seg", True)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.buttons: dict[str, QPushButton] = {}
        layout = hbox(spacing=0, margins=(2, 2, 2, 2))
        for key, text in options:
            btn = QPushButton(tr(text))
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFocusPolicy(Qt.FocusPolicy.TabFocus)
            btn.clicked.connect(lambda _=False, k=key: self.changed.emit(k))
            self.group.addButton(btn)
            self.buttons[key] = btn
            layout.addWidget(btn)
        self.setLayout(layout)
        self.set_current(current or options[0][0])

    def set_current(self, key: str) -> None:
        self.buttons[key].setChecked(True)

    def current(self) -> str:
        for key, btn in self.buttons.items():
            if btn.isChecked():
                return key
        return ""


# ---------------------------------------------------------------- navigation


class NavButton(QAbstractButton):
    """Sidebar item: icon, label, optional mono count. Painted to match .nav."""

    def __init__(self, key: str, text: str, icon_name: str, count: str = ""):
        super().__init__()
        self.key = key
        text = tr(text)
        self.setText(text)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover)
        self.setFixedHeight(34)
        self._icon_name = icon_name
        self._count = count
        self._font = theme.font("sans", 13)
        self._count_font = theme.font("mono", 11)
        self.setAccessibleName(text)

    def set_count(self, count: str) -> None:
        self._count = count
        self.update()

    def sizeHint(self) -> QSize:
        return QSize(200, 34)

    def event(self, e: QEvent) -> bool:
        if e.type() in (QEvent.Type.HoverEnter, QEvent.Type.HoverLeave):
            self.update()
        return super().event(e)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        hovered = self.underMouse()
        checked = self.isChecked()
        if checked or hovered:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(theme.color("accent-bg" if checked else "surface"))
            painter.drawRoundedRect(QRectF(self.rect()), 7, 7)
        if self.hasFocus():
            painter.setPen(theme.color("accent-d"))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 7, 7)
        lit = checked or hovered
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        w = self.width()
        pix = icons.pixmap(self._icon_name, "text" if lit else "muted", 16)
        painter.drawPixmap(QPoint(w - 26 if rtl else 10, (self.height() - 16) // 2), pix)
        painter.setFont(self._font)
        painter.setPen(theme.color("text" if lit else "muted"))
        start, end = (Qt.AlignmentFlag.AlignRight, Qt.AlignmentFlag.AlignLeft) if rtl else (
            Qt.AlignmentFlag.AlignLeft, Qt.AlignmentFlag.AlignRight)
        text_rect = QRect(44, 0, w - 80, self.height()) if rtl else QRect(36, 0, w - 80, self.height())
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | start, self.text())
        if self._count:
            painter.setFont(self._count_font)
            painter.setPen(theme.color("dim"))
            painter.drawText(QRect(10, 0, w - 20, self.height()), Qt.AlignmentFlag.AlignVCenter | end, self._count)


class TabButton(QAbstractButton):
    """Underlined tab with an optional dim mono count (Findings 18)."""

    def __init__(self, text: str):
        super().__init__()
        self.setText(tr(text))
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover)
        self._count = ""
        self._font = theme.font("sans", 13)
        self._count_font = theme.font("mono", 11)

    def set_count(self, count: int | str | None) -> None:
        self._count = "" if count is None else str(count)
        self.updateGeometry()
        self.update()

    def sizeHint(self) -> QSize:
        width = QFontMetrics(self._font).horizontalAdvance(self.text()) + 28
        if self._count:
            width += QFontMetrics(self._count_font).horizontalAdvance(self._count) + 4
        return QSize(width, 38)

    def event(self, e: QEvent) -> bool:
        if e.type() in (QEvent.Type.HoverEnter, QEvent.Type.HoverLeave):
            self.update()
        return super().event(e)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        lit = self.isChecked() or self.underMouse()
        painter.setFont(self._font)
        painter.setPen(theme.color("text" if lit else "muted"))
        metrics = QFontMetrics(self._font)
        text_width = metrics.horizontalAdvance(self.text())
        rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        text_x = self.width() - 14 - text_width if rtl else 14
        painter.drawText(QRect(text_x, 0, text_width + 2, self.height() - 2), Qt.AlignmentFlag.AlignVCenter, self.text())
        if self._count:
            painter.setFont(self._count_font)
            painter.setPen(theme.color("dim"))
            count_w = QFontMetrics(self._count_font).horizontalAdvance(self._count) + 2
            count_x = text_x - 4 - count_w if rtl else 14 + text_width + 4
            painter.drawText(QRect(count_x, 0, count_w, self.height() - 2), Qt.AlignmentFlag.AlignVCenter, self._count)
        if self.isChecked():
            painter.fillRect(QRect(0, self.height() - 2, self.width(), 2), theme.color("accent"))
        if self.hasFocus():
            painter.setPen(theme.color("accent-d"))
            painter.drawRect(self.rect().adjusted(0, 0, -1, -3))


class Tabs(QWidget):
    """Tab strip with a bottom rule plus a stacked page area."""

    changed = Signal(str)

    def __init__(self):
        super().__init__()
        self._group = QButtonGroup(self)
        self._buttons: dict[str, TabButton] = {}
        self._pages: dict[str, QWidget] = {}
        strip = QFrame()
        strip.setObjectName("TabStrip")
        strip.setStyleSheet(f"#TabStrip {{ border-bottom: 1px solid {theme.tokens()['border']}; }}")
        self._strip_layout = hbox(spacing=2)
        self._strip_layout.addStretch(1)
        strip.setLayout(self._strip_layout)
        self.stack = QStackedWidget()
        self.setLayout(vbox(strip, 16, self.stack, spacing=0))

    def add_tab(self, key: str, title: str, page: QWidget) -> TabButton:
        tab = TabButton(title)
        tab.clicked.connect(lambda _=False, k=key: self.set_current(k))
        self._group.addButton(tab)
        self._strip_layout.insertWidget(self._strip_layout.count() - 1, tab)
        self._buttons[key] = tab
        self._pages[key] = page
        self.stack.addWidget(page)
        if len(self._buttons) == 1:
            self.set_current(key)
        return tab

    def set_count(self, key: str, count: int | None) -> None:
        self._buttons[key].set_count(count)

    def set_current(self, key: str) -> None:
        self._buttons[key].setChecked(True)
        self.stack.setCurrentWidget(self._pages[key])
        self.changed.emit(key)

    def current(self) -> str:
        page = self.stack.currentWidget()
        return next(k for k, p in self._pages.items() if p is page)


# ---------------------------------------------------------------- screens


class Screen(QScrollArea):
    """Scrollable page with the prototype's padding (24/28/40) and 1224px content cap."""

    title = ""

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)  # never clip content
        holder = QWidget()
        holder.setObjectName("ScreenContent")
        outer = QHBoxLayout(holder)
        outer.setContentsMargins(28, 24, 28, 40)
        outer.setSpacing(0)
        self.content = QWidget()
        self.content.setMaximumWidth(1224)  # prototype: 1280 max-width box minus 28+28 padding
        self.layout_ = QVBoxLayout(self.content)
        self.layout_.setContentsMargins(0, 0, 0, 0)
        self.layout_.setSpacing(14)
        outer.addWidget(self.content, 1)
        outer.addStretch(0)
        self.setWidget(holder)
        self.viewport().setAutoFillBackground(False)
        holder.setAutoFillBackground(False)

    def make_header(
        self, title: str, sub: str = "", actions: Sequence[QWidget] = (), kicker: str = ""
    ) -> tuple[QLabel, QLabel, QLabel]:
        kicker_label = label(kicker, "hint", mono=True)
        kicker_label.setVisible(bool(kicker))
        title_label = label(tr(title), "h1", selectable=True)
        sub_label = label(tr(sub), "sub", wrap=True)
        sub_label.setVisible(bool(sub))
        text = vbox(kicker_label, title_label, sub_label, spacing=2)
        row = hbox(spacing=8)
        row.addLayout(text, 1)
        for action in actions:
            row.addWidget(action)
        for action in actions:
            row.setAlignment(action, Qt.AlignmentFlag.AlignBottom)
        self.layout_.addLayout(row)
        self.layout_.addSpacing(6)
        return kicker_label, title_label, sub_label

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        for child in self.findChildren(ResponsiveColumns):
            child._place(available_width(child) < child.breakpoint)

    def on_show(self) -> None:
        """Called by the main window each time the screen becomes current."""


class ToggleSwitch(QAbstractButton):
    """34x19 switch (.toggle in the prototype). `danger` paints the on state red."""

    def __init__(self, checked: bool = False, danger: bool = False, accessible_name: str = ""):
        super().__init__()
        self.setCheckable(True)
        self.setChecked(checked)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setFixedSize(34, 19)
        self._danger = danger
        if accessible_name:
            self.setAccessibleName(accessible_name)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        on = self.isChecked()
        enabled = self.isEnabled()
        track = theme.color("accent-d" if on else "surface3")
        if self._danger and on:
            track = QColor("#b9474a")  # prototype .toggle.red.on
        border = track if on else theme.color("border2")
        if not enabled:
            painter.setOpacity(0.45)
        painter.setPen(border)
        painter.setBrush(track)
        painter.drawRoundedRect(QRectF(0.5, 0.5, 33, 18), 9.5, 9.5)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(theme.color("text") if on else theme.color("muted"))
        x = 17 if on else 3
        painter.drawEllipse(QRectF(x, 3, 13, 13))
        if self.hasFocus():
            painter.setOpacity(1)
            painter.setPen(theme.color("accent"))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(QRectF(0.5, 0.5, 33, 18), 9.5, 9.5)



def chip_button(text: str) -> QPushButton:
    chip = QPushButton(tr(text))
    chip.setProperty("chip", True)
    chip.setCheckable(True)
    chip.setCursor(Qt.CursorShape.PointingHandCursor)
    chip.setFocusPolicy(Qt.FocusPolicy.TabFocus)
    chip.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    return chip


class WrapText(QTextBrowser):
    """Read-only text that wraps anywhere (hashes, URLs, paths) and grows to fit its content.

    QLabel can only wrap at spaces, so long tokens would push panels wider than the window.
    Text stays selectable and copyable; links emit `link` instead of navigating.
    """

    link = Signal(str)

    def __init__(self, mono: bool = False, tone: str = "muted"):
        super().__init__()
        self.setReadOnly(True)
        self.setOpenLinks(False)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.document().setDocumentMargin(0)
        self.setFont(theme.font("mono" if mono else "sans", 12))
        self.setStyleSheet(f"QTextBrowser {{ background: transparent; border: none; padding: 0; "
                           f"color: {theme.tokens()[tone]}; }}")
        self.anchorClicked.connect(lambda url: self.link.emit(url.toString()))
        self.document().contentsChanged.connect(self._fit)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._fit()

    def _fit(self) -> None:
        self.document().setTextWidth(max(1, self.viewport().width()))
        self.setFixedHeight(int(self.document().size().height()) + 4)


class ResponsiveColumns(QWidget):
    """Main + side column side by side when there's room; side drops below the main one when narrow."""

    def __init__(self, main: QWidget, side: QWidget, breakpoint: int = 960, side_width: int = 360,
                 main_stretch: int = 1):
        super().__init__()
        self.main, self.side = main, side
        self.breakpoint, self.side_width = breakpoint, side_width
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(14)
        self.grid.setColumnStretch(0, main_stretch)
        self._stacked: bool | None = None
        self._place(False)

    @property
    def stacked(self) -> bool:
        return bool(self._stacked)

    def _place(self, stacked: bool) -> None:
        if stacked == self._stacked:
            return
        self._stacked = stacked
        self.grid.removeWidget(self.main)
        self.grid.removeWidget(self.side)
        self.grid.addWidget(self.main, 0, 0, Qt.AlignmentFlag.AlignTop)
        if stacked:
            self.side.setMaximumWidth(16777215)
            self.grid.addWidget(self.side, 1, 0, Qt.AlignmentFlag.AlignTop)
        else:
            self.side.setMaximumWidth(self.side_width)
            self.grid.addWidget(self.side, 0, 1, Qt.AlignmentFlag.AlignTop)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._place(available_width(self) < self.breakpoint)


def available_width(widget: QWidget) -> int:
    """Visible width for page content: the enclosing scroll area's viewport, not the (possibly
    wider) minimum size of the content itself."""
    parent = widget.parentWidget()
    while parent is not None and not isinstance(parent, QScrollArea):
        parent = parent.parentWidget()
    if parent is None:
        return widget.width()
    return parent.viewport().width() - 56  # Screen padding (28 + 28)


def legend_html(items: Sequence[tuple[str, str]]) -> str:
    """Tag legend as wrapping rich text (a row of widgets can't wrap on narrow windows)."""
    tones = {"local": "green", "external": "amber", "passive": "blue", "active": "red", "api_key": "violet",
             "oss": "muted"}
    toks = theme.tokens()
    parts = []
    for kind, text in items:
        color = toks[tones[kind]]
        badge = (f'<span style="color:{color}; font-size:10px; font-weight:700;">'
                 f'&nbsp;{tr(TAG_TEXT[kind]).upper()}&nbsp;</span>')
        parts.append(f'{badge} <span style="color:{toks["muted"]}; font-size:12px;">{tr(text)}</span>')
    return " &nbsp;&nbsp; ".join(parts)
