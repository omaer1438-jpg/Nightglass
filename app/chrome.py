"""Window chrome: custom title bar, sidebar, status bar and resize grips."""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QMouseEvent, QPainter, QPaintEvent
from PySide6.QtWidgets import QButtonGroup, QFrame, QLabel, QPushButton, QSizePolicy, QWidget

from app import __version__, icons, theme
from app.i18n import tr
from app.widgets import NavButton, hbox, label, vbox

# Segoe Fluent Icons / MDL2 code points for caption buttons.
GLYPH_MINIMIZE, GLYPH_MAXIMIZE, GLYPH_RESTORE, GLYPH_CLOSE = "", "", "", ""


APP_ID = "Nightglass.Desktop"
class TitleBar(QFrame):
    """36px bar: logo, name, breadcrumb, active-case pill, caption buttons."""

    def __init__(self, window: QWidget):
        super().__init__()
        self.setObjectName("TitleBar")
        self.setFixedHeight(36)
        self._window = window

        logo = QLabel()
        logo.setPixmap(icons.logo(16))
        name = label("Nightglass", name="TitleName")
        self.crumb = label("/ Dashboard", name="TitleCrumb")
        self.case_pill = QLabel()
        self.case_pill.setObjectName("CasePill")
        self.case_pill.setTextFormat(Qt.TextFormat.RichText)
        self.case_pill.setFixedHeight(22)

        self.btn_min = self._caption(GLYPH_MINIMIZE, "Minimize", window.showMinimized)
        self.btn_max = self._caption(GLYPH_MAXIMIZE, "Maximize", self._toggle_maximized)
        self.btn_close = self._caption(GLYPH_CLOSE, "Close", window.close)
        self.btn_close.setObjectName("WinClose")

        captions = hbox(self.btn_min, self.btn_max, self.btn_close, spacing=0)
        row = hbox(logo, name, self.crumb, None, self.case_pill, captions, spacing=10, margins=(12, 0, 0, 0))
        self.setLayout(row)
        self.set_case(None, None)

    def _caption(self, glyph: str, tip: str, slot) -> QPushButton:
        btn = QPushButton(glyph)
        btn.setProperty("winbtn", True)
        btn.setToolTip(tr(tip))
        btn.setAccessibleName(tr(tip))
        btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn.clicked.connect(slot)
        return btn

    def _toggle_maximized(self) -> None:
        if self._window.isMaximized():
            self._window.showNormal()
        else:
            self._window.showMaximized()

    def sync_maximized(self, maximized: bool) -> None:
        self.btn_max.setText(GLYPH_RESTORE if maximized else GLYPH_MAXIMIZE)
        self.btn_max.setToolTip(tr("Restore" if maximized else "Maximize"))
        self.btn_max.setAccessibleName(self.btn_max.toolTip())

    def set_crumb(self, text: str) -> None:
        self.crumb.setText(f"/ {tr(text)}")

    def set_case(self, ref: str | None, name: str | None) -> None:
        if ref is None:
            self.case_pill.setText(tr("No active case"))
            return
        accent = theme.tokens()["accent"]
        safe = (name or "").replace("&", "&amp;").replace("<", "&lt;")
        if len(safe) > 48:
            safe = safe[:47] + "…"
        self.case_pill.setText(f'Active case: <b style="color:{accent}">{ref}</b> · {safe}')

    # Dragging and double-click maximize; Windows snap works via startSystemMove.
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self._window.windowHandle():
            self._window.windowHandle().startSystemMove()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._toggle_maximized()
            event.accept()


class Sidebar(QFrame):
    """224px navigation column. Emits navigate(key)."""

    navigate = Signal(str)

    ITEMS = [
        ("dashboard", "Dashboard", "dash", None),
        ("newcase", "New Case", "plus", None),
        ("case", "Case Workspace", "case", None),
        ("Investigate", None, None, None),
        ("modules", "Modules", "mod", "25"),
        ("run", "Run Console", "play", None),
        ("library", "Tool Library", "lib", None),
        ("Output", None, None, None),
        ("reports", "Reports", "rep", None),
        ("settings", "Settings", "set", None),
        ("design", "Design System", "ds", None),
    ]

    def __init__(self, data_dir: str):
        super().__init__()
        self.setObjectName("Sidebar")
        self.setFixedWidth(224)
        self.buttons: dict[str, NavButton] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        wordmark = QLabel()
        wordmark.setPixmap(icons.lockup(34))
        wordmark.setAccessibleName("Nightglass")
        brand_ver = label(f"v{__version__[:3]} · private build", name="BrandVersion")
        brand_ver.setContentsMargins(47, 0, 0, 0)  # aligns under the wordmark, past the owl
        brand = vbox(wordmark, brand_ver, spacing=2, margins=(8, 6, 8, 16))

        layout = vbox(brand, spacing=2, margins=(10, 12, 10, 10))
        for key, text, icon_name, count in self.ITEMS:
            if text is None:
                section = label(key.upper(), "navlabel")
                f = section.font()
                f.setLetterSpacing(f.SpacingType.AbsoluteSpacing, 1.2)
                section.setFont(f)
                layout.addWidget(section)
                continue
            btn = NavButton(key, text, icon_name, count or "")
            btn.clicked.connect(lambda _=False, k=key: self.navigate.emit(k))
            btn.toggled.connect(lambda _=False: self.update())
            self._group.addButton(btn)
            self.buttons[key] = btn
            layout.addWidget(btn)
        layout.addStretch(1)

        foot = QFrame()
        foot.setObjectName("SidebarFoot")
        self.storage_label = self._dot_label("Storage: local", "green")
        self.active_label = self._dot_label("Active modules: off", "red")
        self.path_label = label(_shorten_path(data_dir), "footpath")
        self.path_label.setToolTip(data_dir)
        credit = label("Made by: Omar Al-Olayan", "foot", name="MadeBy")
        foot.setLayout(vbox(self.storage_label, self.active_label, self.path_label, credit,
                            spacing=8, margins=(8, 12, 8, 2)))
        layout.addWidget(foot)
        self.setLayout(layout)

    @staticmethod
    def _dot_label(text: str, tone: str) -> QLabel:
        color = theme.tokens()[tone]
        widget = QLabel(f'<span style="color:{color}">●</span>&nbsp; {text}')
        widget.setTextFormat(Qt.TextFormat.RichText)
        widget.setProperty("role", "foot")
        return widget

    def set_current(self, key: str) -> None:
        if key in self.buttons:
            self.buttons[key].setChecked(True)
        self.update()

    def set_storage(self, encrypted: bool) -> None:
        color = theme.tokens()["green" if encrypted else "amber"]
        text = "Storage: local · encrypted" if encrypted else "Storage: local · unencrypted"
        self.storage_label.setText(f'<span style="color:{color}">●</span>&nbsp; {tr(text)}')

    def set_active_modules(self, enabled: int) -> None:
        tone, text = ("amber", f"Active modules: {enabled} on") if enabled else ("red", "Active modules: off")
        color = theme.tokens()[tone]
        self.active_label.setText(f'<span style="color:{color}">●</span>&nbsp; {text}')

    def set_count(self, key: str, text: str) -> None:
        self.buttons[key].set_count(text)

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        # Accent bar at the sidebar's left edge, beside the current item (.nav.on::before).
        checked = self._group.checkedButton()
        if checked is None:
            return
        geo = checked.geometry()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(theme.color("accent"))
        x = self.width() - 3 if self.layoutDirection() == Qt.LayoutDirection.RightToLeft else -3
        painter.drawRoundedRect(QRectF(x, geo.top() + 8, 6, geo.height() - 16), 3, 3)


def _shorten_path(path: str) -> str:
    parts = path.replace("/", "\\").split("\\")
    if len(parts) <= 4:
        return "\\".join(parts)
    return "\\".join([parts[0], parts[1], "…", *parts[-2:]])


class StatusBar(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("StatusBar")
        self.setFixedHeight(26)
        self.state = label("● Ready", tone="green")
        self.case = label("No case")
        self.db = label("DB: local · unencrypted")
        self.network = label("Network: consent required")
        self.message = label("")
        self.version = label(f"Nightglass v{__version__[:3]}")
        row = hbox(
            self.state, self.case, self.db, self.network, None, self.message, self.version,
            spacing=18, margins=(12, 0, 12, 0),
        )
        self.setLayout(row)
        self.message.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.message.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

    def set_case(self, ref: str | None) -> None:
        self.case.setText(ref or "No case")


class ResizeGrip(QWidget):
    """Invisible strip on a window edge that starts a native resize."""

    def __init__(self, window: QWidget, edges: Qt.Edge):
        super().__init__(window)
        self._window = window
        self.edges = edges
        horizontal = bool(edges & (Qt.Edge.LeftEdge | Qt.Edge.RightEdge))
        vertical = bool(edges & (Qt.Edge.TopEdge | Qt.Edge.BottomEdge))
        if horizontal and vertical:
            diagonal_main = edges in (Qt.Edge.TopEdge | Qt.Edge.LeftEdge, Qt.Edge.BottomEdge | Qt.Edge.RightEdge)
            self.setCursor(Qt.CursorShape.SizeFDiagCursor if diagonal_main else Qt.CursorShape.SizeBDiagCursor)
        elif horizontal:
            self.setCursor(Qt.CursorShape.SizeHorCursor)
        else:
            self.setCursor(Qt.CursorShape.SizeVerCursor)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self._window.windowHandle():
            self._window.windowHandle().startSystemResize(self.edges)
            event.accept()


GRIP_EDGES = [
    Qt.Edge.LeftEdge,
    Qt.Edge.RightEdge,
    Qt.Edge.TopEdge,
    Qt.Edge.BottomEdge,
    Qt.Edge.TopEdge | Qt.Edge.LeftEdge,
    Qt.Edge.TopEdge | Qt.Edge.RightEdge,
    Qt.Edge.BottomEdge | Qt.Edge.LeftEdge,
    Qt.Edge.BottomEdge | Qt.Edge.RightEdge,
]


def place_grips(window: QWidget, grips: list[ResizeGrip], t: int = 5) -> None:
    w, h, c = window.width(), window.height(), t * 2
    E = Qt.Edge
    rects = {
        E.LeftEdge: (0, c, t, h - 2 * c),
        E.RightEdge: (w - t, c, t, h - 2 * c),
        E.TopEdge: (c, 0, w - 2 * c, t),
        E.BottomEdge: (c, h - t, w - 2 * c, t),
        E.TopEdge | E.LeftEdge: (0, 0, c, c),
        E.TopEdge | E.RightEdge: (w - c, 0, c, c),
        E.BottomEdge | E.LeftEdge: (0, h - c, c, c),
        E.BottomEdge | E.RightEdge: (w - c, h - c, c, c),
    }
    for grip in grips:
        grip.setGeometry(*rects[grip.edges])
        grip.raise_()


def apply_windows_frame_tweaks(window: QWidget) -> None:
    """Windows 11: rounded corners and taskbar minimize for the frameless window."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        hwnd = wintypes.HWND(int(window.winId()))
        # DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2
        preference = ctypes.c_int(2)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(preference), ctypes.sizeof(preference))
        # WS_MINIMIZEBOX | WS_MAXIMIZEBOX let the taskbar button minimize/restore the window.
        GWL_STYLE = -16
        user32 = ctypes.windll.user32
        user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
        user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.SetWindowLongPtrW.restype = ctypes.c_ssize_t
        user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
        style = user32.GetWindowLongPtrW(hwnd, GWL_STYLE)
        user32.SetWindowLongPtrW(hwnd, GWL_STYLE, style | 0x00020000 | 0x00010000)
        _set_taskbar_identity(hwnd)
    except (OSError, AttributeError):
        pass  # cosmetic only


def _set_taskbar_identity(hwnd) -> None:
    """Store Python is a packaged app: the taskbar shows its logo unless the window itself names another app."""
    import ctypes

    class PropVariant(ctypes.Structure):
        _fields_ = [("vt", ctypes.c_ushort), ("reserved", ctypes.c_ushort * 3), ("value", ctypes.c_wchar_p),
                    ("padding", ctypes.c_void_p)]

    iid_property_store = uuid.UUID("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99").bytes_le
    app_user_model = uuid.UUID("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3").bytes_le
    launcher = Path(__file__).resolve().parent.parent / "Nightglass.pyw"
    command = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, str(launcher)]
    # Without an icon and relaunch command the taskbar falls back to the generic app icon. The ID goes last.
    properties = ((2, subprocess.list2cmdline(command)), (3, f"{icons.ICO_PATH},0"), (4, "Nightglass"), (5, APP_ID))
    store = ctypes.c_void_p()
    if ctypes.windll.shell32.SHGetPropertyStoreForWindow(hwnd, iid_property_store, ctypes.byref(store)):
        return
    methods = ctypes.cast(store, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    set_value = ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(PropVariant))(methods[6])
    release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(methods[2])
    VT_LPWSTR = 31
    for key, value in properties:
        set_value(store, app_user_model + key.to_bytes(4, "little"), ctypes.byref(PropVariant(vt=VT_LPWSTR, value=value)))
    release(store)
