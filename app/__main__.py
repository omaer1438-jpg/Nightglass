"""Entry point: python -m app"""

from __future__ import annotations

import faulthandler
import gc
import os
import sys
import traceback

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QMessageBox

from app import __version__, i18n, icons, theme
from app.chrome import APP_ID
from app.main_window import MainWindow
from app.security import open_database
from app.state import AppState
from core import paths
from core.catalog import integrity_problem
from core.retention import purge_expired


def _set_windows_app_id() -> None:
    """Group the taskbar button under Nightglass instead of python.exe."""
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        except (OSError, AttributeError):
            pass


def _enable_crash_log() -> None:
    """The windowed build has no console: keep hard crashes and uncaught exceptions in the data folder."""
    paths.data_dir().mkdir(parents=True, exist_ok=True)
    log = open(paths.data_dir() / "crash.log", "a", encoding="utf-8")
    faulthandler.enable(file=log)
    previous = sys.excepthook

    def hook(kind, value, tb) -> None:
        traceback.print_exception(kind, value, tb, file=log)
        log.flush()
        if sys.stderr is not None:
            previous(kind, value, tb)

    sys.excepthook = hook


def _single_instance_lock():
    """The open lock file, or None if another Nightglass already uses this data folder.

    Two instances would each rewrite the whole (encrypted) database and lose the other's writes.
    The OS releases the lock when the process ends, even after a crash.
    """
    paths.data_dir().mkdir(parents=True, exist_ok=True)
    handle = open(paths.data_dir() / "nightglass.lock", "a+b")
    if sys.platform == "win32":
        import msvcrt

        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            handle.close()
            return None
    return handle


def _collect_on_main_thread(app: QApplication) -> None:
    """Module runs allocate on worker threads, and a GC pass there frees widgets the wrong way and corrupts memory."""
    gc.disable()
    timer = QTimer(app, interval=10_000)
    timer.timeout.connect(gc.collect)
    timer.start()


def self_check(report_path: str) -> int:
    """Packaging check: load catalog, modules and pinned binaries, write a JSON report, exit."""
    import json

    from core.catalog import load_catalog
    from core.modules import discover
    from core.runner import CommandError, tool_program

    catalog = load_catalog()
    report = {
        "version": __version__,
        "root": str(paths.PROJECT_ROOT),
        "tools": len(catalog.tools),
        "manifest_errors": [f"{e.file}: {e.message}" for e in catalog.errors],
        "modules": [m.title for m in discover()],
        "theme": theme.QSS_PATH.is_file(),
    }
    exiftool = catalog.get("exiftool")
    try:
        tool_program(exiftool)
        report["exiftool"] = "ok (hash verified)"
    except CommandError as exc:
        report["exiftool"] = str(exc)
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    numbers = [int(m.number) for m in discover()]  # 1..N with no gap: no adapter went missing from the build
    complete = bool(numbers) and numbers == list(range(1, len(numbers) + 1))
    return 0 if not catalog.errors and complete and report["theme"] else 1


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--self-check":
        return self_check(sys.argv[2])
    _enable_crash_log()
    _set_windows_app_id()
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName("Nightglass")
    app.setApplicationVersion(__version__)
    app.setWindowIcon(icons.app_icon())
    theme.apply_theme(app)
    _collect_on_main_thread(app)

    lock = _single_instance_lock()
    if lock is None:
        QMessageBox.information(None, "Nightglass", "Nightglass is already running. Switch to its window: "
                                "two copies would overwrite each other's case data.")
        return 0

    db = open_database()
    if db is None:
        return 0  # unlock cancelled
    i18n.set_language(db.get_setting("language", "en"))
    if i18n.is_rtl():
        app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    removed = purge_expired(db)  # closed cases past their retention period
    state = AppState(db)
    window = MainWindow(state, str(paths.data_dir()))
    if removed:
        window.show_message(f"Retention: deleted {', '.join(removed)} (closed past the retention period).")
    # ExifTool (launcher + its whole exiftool_files tree, ~0.3 s); bigger pinned binaries are checked on first use.
    tampered = [p for t in state.catalog.tools if t.launch.tree and (p := integrity_problem(t))
                and "not installed" not in p]
    if tampered:
        window.show_message(tampered[0])

    screen = app.primaryScreen().availableGeometry()
    width, height = min(1480, int(screen.width() * 0.9)), min(940, int(screen.height() * 0.9))
    window.resize(width, height)
    window.move(screen.center().x() - width // 2, screen.center().y() - height // 2)
    window.show()

    code = app.exec()
    db.close()
    _hard_exit(code)


def _hard_exit(code: int) -> None:
    """Skip Qt's teardown, which crashes at exit. os._exit still unloads DLLs and crashes there too
    (an access violation in crash.log on every close), so on Windows end the process outright."""
    # shortcut: remove when a PySide update exits cleanly
    faulthandler.disable()
    sys.stdout and sys.stdout.flush()
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.TerminateProcess(kernel32.GetCurrentProcess(), code)
    os._exit(code)


if __name__ == "__main__":
    sys.exit(main())
