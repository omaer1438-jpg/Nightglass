"""Settings: turning database encryption on and off (restart is stubbed)."""

from __future__ import annotations

import pytest

import app.screens.settings as settings_screen
from app.main_window import MainWindow
from app.security import SetPasswordDialog, UnlockDialog
from app.state import AppState
from core import paths
from core.cases import CaseManager
from core.db import Database
from core.dbcrypto import DbCrypto

PASSWORD = "example-master-passphrase"


@pytest.fixture
def ui(qtbot, themed_app, new_case, monkeypatch):
    db = Database(paths.db_path())
    state = AppState(db)
    CaseManager(db).create_case(new_case())
    window = MainWindow(state, str(paths.data_dir()))
    qtbot.addWidget(window)
    window.show()
    restarts = []
    monkeypatch.setattr(settings_screen, "relaunch", lambda: restarts.append(True))
    yield window, state, restarts
    window.close()


def test_turn_encryption_on_then_off(ui, monkeypatch):
    window, state, restarts = ui
    screen = window.screens["settings"]

    def set_password(dialog):
        dialog.first.setText(PASSWORD)
        dialog.second.setText(PASSWORD + "x")
        dialog.understand.setChecked(True)
        dialog._try()
        assert dialog.error.text() == "The two passwords don't match."
        dialog.second.setText(PASSWORD)
        dialog._try()
        return 1

    monkeypatch.setattr(SetPasswordDialog, "exec", set_password)
    screen.encrypt.click()
    assert restarts == [True]
    assert paths.encrypted_db_path().exists()
    assert not paths.db_path().exists() and not paths.db_path().with_name("nightglass.db-wal").exists()
    assert b"Account impersonation" not in paths.encrypted_db_path().read_bytes()

    crypto, data = DbCrypto.unlock(paths.encrypted_db_path(), PASSWORD)
    reopened = Database(paths.encrypted_db_path(), crypto=crypto, data=data)
    assert [c.name for c in CaseManager(reopened).list_cases()] == ["Account impersonation review"]
    second = MainWindow(AppState(reopened), str(paths.data_dir()))
    try:
        assert "encrypted" in second.status.db.text()
        assert second.screens["settings"].encrypt.isChecked()

        def unlock(dialog):
            dialog.password.setText("wrong-password-here")
            dialog._try()
            assert not dialog.error.isHidden()
            dialog.password.setText(PASSWORD)
            dialog._try()
            return 1

        monkeypatch.setattr(UnlockDialog, "exec", unlock)
        second.screens["settings"].encrypt.click()
        assert paths.db_path().exists() and not paths.encrypted_db_path().exists()
        with Database(paths.db_path()) as plain:
            assert CaseManager(plain).list_cases()[0].name == "Account impersonation review"
    finally:
        second._restarting = True
        second.close()


def test_cancel_keeps_database_plain(ui, monkeypatch):
    window, state, restarts = ui
    monkeypatch.setattr(SetPasswordDialog, "exec", lambda self: 0)
    window.screens["settings"].encrypt.click()
    assert not window.screens["settings"].encrypt.isChecked()
    assert restarts == [] and not paths.encrypted_db_path().exists()
