"""Master-password dialogs, encryption on/off, Windows EFS for the cases folder, relaunch."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QProcess, Qt
from PySide6.QtWidgets import QApplication, QCheckBox, QLineEdit

from app.dialogs import Modal
from app.widgets import button, label
from core import paths
from core.db import Database, decrypt_existing, encrypt_existing
from core.dbcrypto import DbCrypto, NotEncryptedFile, WrongPassword, check_password_strength

FILE_ATTRIBUTE_ENCRYPTED = 0x4000


def _password_field(placeholder: str) -> QLineEdit:
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    field.setPlaceholderText(placeholder)
    return field


class UnlockDialog(Modal):
    """Asks for the master password and returns the unlocked database."""

    def __init__(self, enc_path: Path, title: str = "Unlock Nightglass", action: str = "Unlock"):
        super().__init__(None, width=440)
        self.enc_path = enc_path
        self.result_db: tuple[DbCrypto, bytes] | None = None
        self.header("lock", "accent", title, "The case database is encrypted. Enter your master password.")
        body = self.content()
        self.password = _password_field("Master password")
        self.error = label("", "error", wrap=True)
        self.error.hide()
        body.addWidget(self.password)
        body.addWidget(self.error)
        self.ok = button(action, "primary", on_click=self._try, name="UnlockOk")
        self.ok.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.footer(label("A forgotten password can't be recovered.", "hint"), None,
                    button("Cancel", "ghost", on_click=self.reject), self.ok)
        self.password.returnPressed.connect(self._try)
        self.password.setFocus()

    def _try(self) -> None:
        try:
            self.result_db = DbCrypto.unlock(self.enc_path, self.password.text())
        except WrongPassword as exc:
            self.error.setText(str(exc))
            self.error.show()
            self.password.selectAll()
            return
        except NotEncryptedFile as exc:
            self.error.setText(str(exc))
            self.error.show()
            return
        self.password.clear()
        self.accept()


class SetPasswordDialog(Modal):
    def __init__(self, parent, title: str = "Encrypt the case database"):
        super().__init__(parent, width=480)
        self.header("lock", "amber", title,
                    "Nightglass will ask for this password every time it starts. The database is "
                    "AES-256 encrypted on disk and only decrypted in memory.")
        body = self.content()
        self.first = _password_field("New master password (at least 10 characters)")
        self.second = _password_field("Repeat the password")
        self.understand = QCheckBox("I understand that a forgotten password means the cases are lost for good.")
        self.error = label("", "error", wrap=True)
        self.error.hide()
        for widget in (self.first, self.second, self.understand, self.error):
            body.addWidget(widget)
        self.ok = button("Encrypt", "primary", on_click=self._try, name="SetPasswordOk")
        self.ok.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.footer(None, button("Cancel", "ghost", on_click=self.reject), self.ok)
        self.password = ""

    def _try(self) -> None:
        problem = check_password_strength(self.first.text())
        if problem is None and self.first.text() != self.second.text():
            problem = "The two passwords don't match."
        if problem is None and not self.understand.isChecked():
            problem = "Tick the box to confirm you understand the password can't be recovered."
        if problem:
            self.error.setText(problem)
            self.error.show()
            return
        self.password = self.first.text()
        self.first.clear()
        self.second.clear()
        self.accept()


# ---------------------------------------------------------------- startup


def open_database() -> Database | None:
    """Plain or encrypted database for this session; None if the user cancels the unlock."""
    enc = paths.encrypted_db_path()
    if enc.exists():
        dialog = UnlockDialog(enc)
        if not dialog.exec():
            return None
        crypto, data = dialog.result_db
        return Database(enc, crypto=crypto, data=data)
    return Database(paths.db_path())


def relaunch() -> None:
    """Start a new Nightglass process and quit this one (after switching database mode)."""
    args = sys.argv[1:] if getattr(sys, "frozen", False) else ["-m", "app"]
    QProcess.startDetached(sys.executable, args, str(paths.PROJECT_ROOT))
    QApplication.instance().quit()


# ---------------------------------------------------------------- switching modes


def enable_encryption(state, password: str) -> None:
    """Plain -> encrypted. The caller restarts the app afterwards."""
    data = state.db.serialize()
    state.db.close()
    encrypt_existing(paths.db_path(), paths.encrypted_db_path(), password, data=data)


def disable_encryption(state) -> None:
    """Encrypted -> plain (after the caller re-checked the password)."""
    data = state.db.serialize()
    state.db.close()
    decrypt_existing(paths.encrypted_db_path(), paths.db_path(), data)


# ---------------------------------------------------------------- Windows EFS


def efs_enabled(folder: Path) -> bool:
    try:
        return bool(folder.stat().st_file_attributes & FILE_ATTRIBUTE_ENCRYPTED)
    except (OSError, AttributeError):
        return False


def set_efs(folder: Path, on: bool) -> tuple[bool, str]:
    """cipher /e|/d /s:<folder> - fixed argument list, no shell. Returns (ok, message)."""
    folder.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["cipher", "/e" if on else "/d", f"/s:{folder}"],
            capture_output=True, text=True, timeout=600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Windows EFS could not run: {type(exc).__name__}."
    if result.returncode != 0 or efs_enabled(folder) != on:
        detail = (result.stdout or result.stderr).strip().splitlines()[-1:] or ["no details"]
        return False, f"Windows EFS failed: {detail[0]}"
    return True, ("Cases folder encrypted with Windows EFS (tied to your Windows account)." if on
                  else "Windows EFS turned off for the cases folder.")
