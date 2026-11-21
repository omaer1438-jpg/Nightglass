"""Main window: frameless shell with title bar, sidebar, screens and status bar."""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtGui import QCloseEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import QFrame, QStackedWidget, QWidget

from app import icons
from app.chrome import (
    GRIP_EDGES,
    ResizeGrip,
    Sidebar,
    StatusBar,
    TitleBar,
    apply_windows_frame_tweaks,
    place_grips,
)
from app.screens.case_workspace import CaseWorkspaceScreen
from app.screens.dashboard import DashboardScreen
from app.screens.design import DesignScreen
from app.screens.library import LibraryScreen
from app.screens.modules import ModulesScreen
from app.screens.reports import ReportsScreen
from app.screens.run_console import RunConsoleScreen
from app.screens.settings import SettingsScreen
from app.screens.new_case import NewCaseScreen
from app.state import AppState
from app.widgets import Screen, hbox, set_prop, vbox
from core.cases import Case

MESSAGE_TIMEOUT_MS = 6000


class MainWindow(QWidget):
    def __init__(self, state: AppState, data_dir: str):
        super().__init__()
        self.state = state
        self.setWindowTitle("Nightglass")
        self.setWindowIcon(icons.app_icon())
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)
        self.setMinimumSize(1100, 680)

        root = QFrame(self)
        root.setObjectName("AppRoot")
        self.root = root
        self.title_bar = TitleBar(self)
        self.sidebar = Sidebar(data_dir)
        self.status = StatusBar()

        self.screens: dict[str, Screen] = {
            "dashboard": DashboardScreen(state),
            "newcase": NewCaseScreen(state),
            "case": CaseWorkspaceScreen(state),
            "modules": ModulesScreen(state),
            "run": RunConsoleScreen(state),
            "library": LibraryScreen(state),
            "settings": SettingsScreen(state),
            "reports": ReportsScreen(state),
            "design": DesignScreen(),
        }
        self.stack = QStackedWidget()
        self.stack.setObjectName("MainArea")
        for key in self.sidebar.buttons:
            self.stack.addWidget(self.screens[key])

        body = hbox(self.sidebar, self.stack, spacing=0)
        root.setLayout(vbox(self.title_bar, body, self.status, spacing=0, margins=(1, 1, 1, 1)))
        self.setLayout(vbox(root, spacing=0))

        self._grips = [ResizeGrip(self, edges) for edges in GRIP_EDGES]
        self._message_timer = QTimer(self, singleShot=True, interval=MESSAGE_TIMEOUT_MS)
        self._message_timer.timeout.connect(lambda: self.status.message.setText(""))

        self.sidebar.navigate.connect(self.navigate)
        state.navigate_requested.connect(self.navigate)
        state.active_case_changed.connect(self._active_case_changed)
        state.message.connect(self.show_message)
        state.catalog_changed.connect(lambda catalog: self.sidebar.set_count("library", str(len(catalog.tools))))
        self.sidebar.set_count("library", str(len(state.catalog.tools)))
        self.sidebar.set_count("modules", str(len(state.modules)))
        self.sidebar.set_storage(state.db.encrypted)
        self.status.db.setText("DB: encrypted (AES-256)" if state.db.encrypted else "DB: local · unencrypted")
        state.settings_changed.connect(self._settings_changed)
        self._settings_changed()
        self._add_shortcuts()

        self._active_case_changed(None)
        state.restore_last_case()
        self.navigate("dashboard")

    def _add_shortcuts(self) -> None:
        """Window-wide keys (Esc closing a modal is in Modal). Screens offer focus_search() for Ctrl+F."""
        QShortcut(QKeySequence("Ctrl+K"), self, activated=self.screens["dashboard"].focus_lookup)
        QShortcut(QKeySequence("Ctrl+N"), self, activated=lambda: self.navigate("newcase"))
        QShortcut(QKeySequence.StandardKey.Find, self, activated=self.focus_search)
        for number, (key, btn) in enumerate(list(self.sidebar.buttons.items())[:9], start=1):
            QShortcut(QKeySequence(f"Ctrl+{number}"), self, activated=lambda k=key: self.navigate(k))
            btn.setToolTip(f"{btn.text()} (Ctrl+{number})")

    def focus_search(self) -> None:
        focus = getattr(self.stack.currentWidget(), "focus_search", None)
        if focus is not None:
            focus()

    # ---- navigation

    def navigate(self, key: str) -> None:
        screen = self.screens[key]
        self.stack.setCurrentWidget(screen)
        self.sidebar.set_current(key)
        self.title_bar.set_crumb(screen.title)
        screen.verticalScrollBar().setValue(0)
        screen.setFocus(Qt.FocusReason.OtherFocusReason)
        screen.on_show()

    def current_key(self) -> str:
        current = self.stack.currentWidget()
        return next(k for k, s in self.screens.items() if s is current)

    def _active_case_changed(self, case: Case | None) -> None:
        if case is None:
            self.title_bar.set_case(None, None)
            self.status.set_case(None)
            self.sidebar.set_count("case", "")
            return
        self.title_bar.set_case(case.ref, case.name)
        self.status.set_case(case.ref + ("" if case.is_open else " · closed"))
        self.sidebar.set_count("case", f"{case.id:03d}")

    def _settings_changed(self) -> None:
        # Every Settings switch a module or tool manifest declares, so new active modules count without edits here.
        keys = {s.active_setting for s in self.state.modules} | {t.active_setting for t in self.state.catalog.tools}
        keys.discard(None)
        self.sidebar.set_active_modules(sum(bool(self.state.db.get_setting(k, False)) for k in keys))

    def show_message(self, text: str) -> None:
        self.status.message.setText(text)
        self._message_timer.start()

    # ---- frameless window behavior

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not getattr(self, "_tweaked", False):
            self._tweaked = True
            apply_windows_frame_tweaks(self)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        place_grips(self, self._grips)

    def changeEvent(self, event: QEvent) -> None:
        if event.type() == QEvent.Type.WindowStateChange:
            maximized = self.isMaximized()
            self.title_bar.sync_maximized(maximized)
            set_prop(self.root, "maximized", maximized)
            for grip in self._grips:
                grip.setVisible(not maximized)
        super().changeEvent(event)

    def prepare_restart(self) -> None:
        """Save everything before the database is closed for an encryption switch."""
        self.state.runner.stop()
        self.screens["case"].flush()
        self._restarting = True

    def closeEvent(self, event: QCloseEvent) -> None:
        if not getattr(self, "_restarting", False):
            self.screens["case"].flush()  # never lose unsaved notes
            self.state.runner.stop()     # never leave a tool process running
        super().closeEvent(event)
