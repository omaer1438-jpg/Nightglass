"""Settings: privacy and storage, active modules, API keys, execution, appearance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QComboBox, QFrame, QGridLayout, QLineEdit, QWidget

from app.dialogs import Modal, Notice
from app.security import (
    SetPasswordDialog,
    UnlockDialog,
    disable_encryption,
    efs_enabled,
    enable_encryption,
    relaunch,
    set_efs,
)
from app.state import AppState, run_in_background
from app.chrome import _shorten_path
from app.i18n import tr
from app.screens.library import fix_hint
from app.widgets import Banner, Card, Screen, Segmented, ToggleSwitch, button, clear_layout, hbox, label, vbox
from core import paths
from core.catalog import availability
from core.manifest import LaunchKind
from core.secrets import INSTAGRAM_LOGIN, KNOWN_KEYS, KeySpec

RETENTION_OPTIONS = [(30, "30 days"), (90, "90 days"), (180, "180 days"), (None, "Never")]
TIMEOUT_OPTIONS = [0, 60, 180, 300, 600]  # 0 = each tool's own limit


class SettingRow(QFrame):
    """.setrow: title + description on the left, a control on the right."""

    def __init__(self, title: str, description: str, *controls: QWidget, mono: bool = False):
        super().__init__()
        self.setProperty("setrow", True)
        self.title = label(title)
        self.title.setStyleSheet("font-weight: 600;")
        self.description = label(description, "muted", wrap=True, mono=mono)
        self.description.setStyleSheet("font-size: 12px;" + (" font-size: 11px;" if mono else ""))
        text = vbox(self.title, self.description, spacing=2)
        row = hbox(spacing=12, margins=(16, 13, 16, 13))
        row.addLayout(text, 1)
        for control in controls:
            row.addWidget(control, 0, Qt.AlignmentFlag.AlignVCenter)
        self.setLayout(row)


class KeyDialog(Modal):
    def __init__(self, parent, spec: KeySpec):
        super().__init__(parent, width=460)
        self.header("lock", "accent", f"{spec.title} API key",
                    "Stored in Windows Credential Manager. It is never written to files, logs or reports.")
        body = self.content()
        self.value = QLineEdit()
        self.value.setEchoMode(QLineEdit.EchoMode.Password)
        self.value.setPlaceholderText("Paste the key")
        self.error = label("", "error", wrap=True)
        self.error.hide()
        body.addWidget(self.value)
        body.addWidget(self.error)
        save = button("Save key", "primary", on_click=self.accept, name="SaveKey")
        self.footer(None, button("Cancel", "ghost", on_click=self.reject), save)
        self.value.returnPressed.connect(self.accept)


class InstagramLoginDialog(Modal):
    def __init__(self, parent):
        super().__init__(parent, width=460)
        self.header("lock", "accent", INSTAGRAM_LOGIN.title,
                    "Stored in Windows Credential Manager. Written to the run folder only for an Osintgram run and "
                    "deleted when it ends. Use a secondary account: Instagram may block or ban it.")
        body = self.content()
        self.username = QLineEdit()
        self.username.setPlaceholderText("Instagram username")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Password")
        self.error = label("", "error", wrap=True)
        self.error.hide()
        for widget in (self.username, self.password, self.error):
            body.addWidget(widget)
        save = button("Save login", "primary", on_click=self.accept, name="SaveInstagram")
        self.footer(None, button("Cancel", "ghost", on_click=self.reject), save)
        self.password.returnPressed.connect(self.accept)


class SettingsScreen(Screen):
    title = "Settings"

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        db = state.db
        self.make_header("Settings", "Privacy first. Everything here is stored on this computer.")

        # ---- privacy & storage
        privacy = self._card("Privacy & storage", icon=("shield", "accent"))
        self.encrypt = ToggleSwitch(db.encrypted, accessible_name="Encrypt case database")
        self.encrypt.toggled.connect(self._encryption_toggled)
        self.change_pw = button("Change password", on_click=self.change_password, name="ChangePassword")
        self.change_pw.setVisible(db.encrypted)
        self.efs = ToggleSwitch(efs_enabled(paths.data_dir()), accessible_name="Encrypt cases folder with EFS")
        self.efs.toggled.connect(self._efs_toggled)
        self.ask = ToggleSwitch(True, accessible_name="Ask before every external lookup")
        self.ask.setEnabled(False)
        self.cache = ToggleSwitch(bool(db.get_setting("cache_external_results", True)),
                                  accessible_name="Cache external results")
        self.cache.toggled.connect(lambda on: self._set("cache_external_results", on))
        clear_cache = button("Clear cache", on_click=self.clear_cache, name="ClearCache")
        open_folder = button("Open folder", icon="folder",
                             on_click=lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(paths.data_dir()))))
        self.retention = QComboBox()
        for days, text in RETENTION_OPTIONS:
            self.retention.addItem(text, days)
        current = db.get_setting("retention_days", 90)
        self.retention.setCurrentIndex(max(0, self.retention.findData(current)))
        self.retention.currentIndexChanged.connect(self._retention_changed)
        for row in (
            SettingRow("Encrypt case database", "AES-256 with a master password asked at launch. Decrypted "
                       "only in memory. A forgotten password can't be recovered.", self.change_pw, self.encrypt),
            SettingRow("Encrypt cases folder (Windows EFS)", "Evidence, reports and run logs, encrypted by "
                       "Windows for your account only. Back up your EFS certificate (certmgr).", self.efs),
            SettingRow("Ask before every external lookup", "Always on. Every external lookup shows the provider "
                       "and data first, and every consent is logged.", self.ask),
            SettingRow("Cache external results", "Avoids repeating the same query for 24 h. Clearing removes "
                       "cached provider answers.", clear_cache, self.cache),
            folder_row := SettingRow("Cases folder", _shorten_path(str(paths.data_dir())), open_folder, mono=True),
            SettingRow("Delete closed cases after", "Closed cases and their folders are removed this long after "
                       "closing (checked at startup).", self.retention),
        ):
            privacy.body_layout.addWidget(row)
        folder_row.description.setToolTip(str(paths.data_dir()))  # shortened so a long path can't widen the column

        # ---- active modules
        active = self._card("Active modules", icon=("warn", "red"))
        active.body_layout.addWidget(self._wrap(Banner(
            "danger", "These touch the target's systems or third-party account flows. Enable only for systems "
                      "you own or are authorized to test. Each run still needs the case scope and a fresh consent.")))
        self.holehe = ToggleSwitch(bool(db.get_setting("active.holehe", False)), danger=True,
                                   accessible_name="Holehe")
        self.holehe.toggled.connect(lambda on: self._set_active("active.holehe", on, self.holehe))
        self.phone = ToggleSwitch(bool(db.get_setting("active.phone_registration", False)), danger=True,
                                  accessible_name="Phone app-registration check")
        self.phone.toggled.connect(lambda on: self._set_active("active.phone_registration", on, self.phone))
        self.portscan = ToggleSwitch(bool(db.get_setting("active.port_scan", False)), danger=True,
                                     accessible_name="Live port scan")
        self.portscan.toggled.connect(lambda on: self._set_active("active.port_scan", on, self.portscan))
        self.wafw00f = ToggleSwitch(bool(db.get_setting("active.wafw00f", False)), danger=True, accessible_name="WafDetect")
        self.wafw00f.toggled.connect(lambda on: self._set_active("active.wafw00f", on, self.wafw00f))
        self.zone_transfer = ToggleSwitch(bool(db.get_setting("active.zone_transfer", False)), danger=True,
                                          accessible_name="ZoneTransfer")
        self.zone_transfer.toggled.connect(lambda on: self._set_active("active.zone_transfer", on, self.zone_transfer))
        for row in (
            SettingRow("Holehe (email registration hints)", "EmailFootprint engine. Checks signup/login forms on ~120 "
                       "sites (password-reset checks skipped).", self.holehe),
            SettingRow("Phone app-registration check", "Module 26 (ignorant): asks Instagram, Snapchat and "
                       "Amazon login/signup forms whether a number is registered.", self.phone),
            SettingRow("Live port scan", "Module 15: TCP connect to 19 allowlisted ports, own assets only.",
                       self.portscan),
            SettingRow("WafDetect", "Module 24: sends a few attack-like test requests to one site.", self.wafw00f),
            SettingRow("ZoneTransfer", "Module 25: asks a domain's name servers for all their records.", self.zone_transfer),
        ):
            active.body_layout.addWidget(row)

        # ---- API keys
        keys = self._card("API keys", right=[label("Stored in Windows Credential Manager", "hint")], icon=("lock", "violet"))
        self.key_rows: dict[str, SettingRow] = {}
        for spec in KNOWN_KEYS:
            add = button("Add key", name=f"KeyAdd_{spec.name}", on_click=lambda _=False, s=spec: self.edit_key(s))
            remove = button("Remove", "ghost", name=f"KeyRemove_{spec.name}",
                            on_click=lambda _=False, s=spec: self.remove_key(s))
            row = SettingRow(spec.title, spec.hint, remove, add)
            row.add_btn, row.remove_btn = add, remove
            self.key_rows[spec.name] = row
            keys.body_layout.addWidget(row)
        self.instagram_set = button("Set", name="InstagramSet", on_click=self.edit_instagram)
        self.instagram_remove = button("Remove", "ghost", name="InstagramRemove", on_click=self.remove_instagram)
        self.instagram_row = SettingRow(INSTAGRAM_LOGIN.title, INSTAGRAM_LOGIN.hint,
                                        self.instagram_remove, self.instagram_set)
        keys.body_layout.addWidget(self.instagram_row)

        # ---- execution
        execution = self._card("Execution", icon=("cpu", "accent"))
        self.timeout = QComboBox()
        for seconds in TIMEOUT_OPTIONS:
            self.timeout.addItem(f"{seconds} s" if seconds else "Tool default", seconds)
        self.timeout.setCurrentIndex(max(0, self.timeout.findData(db.get_setting("timeout_cap_s", 0))))
        self.timeout.currentIndexChanged.connect(lambda: self._set("timeout_cap_s", self.timeout.currentData()))
        self.check_btn = check = button("Check", on_click=self.check_tools, name="CheckTools",
                                        tooltip="Look for each tool's venv or binary and verify pinned hashes")
        self.tools_list = vbox(spacing=4, margins=(16, 0, 16, 12))
        execution.body_layout.addWidget(SettingRow(
            "Timeout limit", "Caps every run. Tool default uses each tool's own limit "
            "(up to 600 s).", self.timeout))
        execution.body_layout.addWidget(SettingRow(
            "Tool environments", "Separate venvs in envs\\ and pinned binaries in bin\\ (hash-checked).", check))
        execution.body_layout.addLayout(self.tools_list)

        # ---- appearance
        appearance = self._card("Appearance")
        theme_seg = Segmented([("dark", "Dark")], current="dark")
        self.results_view = Segmented([("table", "Table"), ("console", "Console")],
                                      current=db.get_setting("results_view", "console"))
        self.results_view.changed.connect(lambda key: self._set("results_view", key))
        self.language = Segmented([("en", "English"), ("ar", "العربية")], current=db.get_setting("language", "en"))
        self.language.changed.connect(self._language_changed)
        appearance.body_layout.addWidget(SettingRow("Theme", "Nightglass has one dark theme.", theme_seg))
        appearance.body_layout.addWidget(SettingRow("Results view", "Default view in the Run Console.",
                                                 self.results_view))
        appearance.body_layout.addWidget(SettingRow("Language", "Arabic switches the layout to right-to-left. "
                                                 "Restart Nightglass to apply.", self.language))

        grid = QGridLayout()
        grid.setSpacing(14)
        grid.addLayout(vbox(privacy, active, None, spacing=14), 0, 0)
        grid.addLayout(vbox(keys, execution, appearance, None, spacing=14), 0, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        self.layout_.addLayout(grid)
        self.layout_.addStretch(1)
        self.refresh_keys()

    @staticmethod
    def _card(title: str, right=(), icon: tuple[str, str] | None = None) -> Card:
        card = Card(title, right=right, padding=(0, 0, 0, 0), icon=icon)
        card.body_layout.setSpacing(0)
        return card

    @staticmethod
    def _wrap(widget: QWidget) -> QWidget:
        holder = QWidget()
        holder.setLayout(vbox(widget, margins=(16, 12, 16, 4)))
        return holder

    def on_show(self) -> None:
        self.refresh_keys()

    # ---- actions

    def _set(self, key: str, value) -> None:
        self.state.db.set_setting(key, value)
        self.state.say("Setting saved.")
        self.state.settings_changed.emit()

    def _set_active(self, key: str, on: bool, switch: ToggleSwitch) -> None:
        if on:
            notice = Notice(self.window(), "Enable this active module?", [
                "It contacts the target's own systems or third-party account flows.",
                "Use it only for systems you own or have written authorization to test.",
                "Each run is still checked against the case scope and needs a fresh consent.",
            ], tone="red", action=("Enable", None))
            notice.exec()
            if not notice.action_taken:
                switch.blockSignals(True)
                switch.setChecked(False)
                switch.blockSignals(False)
                return
        self._set(key, on)

    def _revert(self, switch: ToggleSwitch, value: bool) -> None:
        switch.blockSignals(True)
        switch.setChecked(value)
        switch.blockSignals(False)

    def _encryption_toggled(self, on: bool) -> None:
        window = self.window()
        if self.state.runner.busy:  # the switch closes the database under the run
            self._revert(self.encrypt, not on)
            self.state.say("A module is still running. Stop it or wait for it to finish, then switch encryption.")
            return
        if on:
            dialog = SetPasswordDialog(window)
            if not dialog.exec():
                self._revert(self.encrypt, False)
                return
            window.prepare_restart()
            enable_encryption(self.state, dialog.password)
        else:
            check = UnlockDialog(paths.encrypted_db_path(), "Turn encryption off", "Decrypt")
            check.setParent(window, check.windowFlags())
            if not check.exec():
                self._revert(self.encrypt, True)
                return
            window.prepare_restart()
            disable_encryption(self.state)
        relaunch()

    def change_password(self) -> None:
        check = UnlockDialog(paths.encrypted_db_path(), "Confirm current password", "Continue")
        check.setParent(self.window(), check.windowFlags())
        if not check.exec():
            return
        dialog = SetPasswordDialog(self.window(), "Choose a new master password")
        dialog.ok.setText("Change password")
        if dialog.exec():
            self.state.db.change_password(dialog.password)
            self.state.say("Master password changed.")

    def _efs_toggled(self, on: bool) -> None:
        if self.state.runner.busy:  # cipher would rewrite files a running tool is writing
            self._revert(self.efs, not on)
            self.state.say("A module is still running. Stop it or wait for it to finish, then change EFS.")
            return
        if on:
            notice = Notice(self.window(), "Encrypt the cases folder with Windows EFS?", [
                "Files stay readable only when you're signed in to this Windows account.",
                "Back up your EFS certificate (certmgr → Personal → Certificates). Without it, a reset "
                "Windows account can't read the files.",
            ], tone="amber", action=("Encrypt folder", None))
            notice.exec()
            if not notice.action_taken:
                self._revert(self.efs, False)
                return
        self.efs.setEnabled(False)  # busy until cipher finishes; it can take minutes on a big folder
        self.state.say("Encrypting the cases folder with Windows EFS…" if on else "Turning Windows EFS off…")

        def done(result, error) -> None:
            self.efs.setEnabled(True)
            ok, message = result if error is None else (
                False, f"Windows EFS could not run: {error}. EFS needs Windows Pro and an NTFS drive.")
            if not ok:
                self._revert(self.efs, not on)
            self.state.say(message)

        folder = paths.data_dir()
        run_in_background(lambda: set_efs(folder, on), done)

    def _retention_changed(self) -> None:
        db = self.state.db
        days, old = self.retention.currentData(), db.get_setting("retention_days", 90)
        # Only cases still on the old default follow the new one; a case with its own value keeps it.
        rows = db.execute("SELECT status, closed_at FROM cases WHERE retention_days IS ?", (old,)).fetchall()
        now = datetime.now(timezone.utc)
        doomed = 0 if days is None else sum(
            1 for r in rows if r["status"] == "closed" and r["closed_at"]
            and datetime.fromisoformat(r["closed_at"]) + timedelta(days=days) <= now)
        text = self.retention.currentText()
        notice = Notice(self.window(), f"Delete closed cases after {text.lower()}?" if days else
                        "Keep closed cases until you delete them?", [
            f"Applies to new cases and to the {len(rows)} existing case(s) that use the current default. "
            "Cases with their own retention keep it.",
            f"{doomed} closed case(s) and their folders will be deleted the next time Nightglass starts."
            if doomed else "No closed case would be deleted at the next start.",
        ], tone="red" if doomed else "amber", action=("Change retention", None))
        notice.exec()
        if not notice.action_taken:
            self.retention.blockSignals(True)
            self.retention.setCurrentIndex(max(0, self.retention.findData(old)))
            self.retention.blockSignals(False)
            return
        db.set_setting("retention_days", days)
        db.execute("UPDATE cases SET retention_days = ? WHERE retention_days IS ?", (days, old))
        self.state.say(f"Retention saved for new cases and {len(rows)} existing case(s).")

    def _language_changed(self, key: str) -> None:
        self.state.db.set_setting("language", key)
        self.state.say("Language saved. Restart Nightglass to apply it.")

    def clear_cache(self) -> None:
        removed = self.state.db.execute("DELETE FROM api_cache").rowcount
        self.state.say(f"Cache cleared ({removed} cached answers removed).")

    def refresh_keys(self) -> None:
        for spec in KNOWN_KEYS:
            row = self.key_rows[spec.name]
            masked = self.state.keys.masked(spec.name)
            row.description.setText(masked or spec.hint)
            row.description.setProperty("mono", bool(masked))
            row.description.style().unpolish(row.description)
            row.description.style().polish(row.description)
            row.add_btn.setText("Replace" if masked else "Add key")
            row.remove_btn.setVisible(bool(masked))
        login = self.state.keys.login(INSTAGRAM_LOGIN.name)
        self.instagram_row.description.setText(f"@{login[0]} · password ••••••••" if login else INSTAGRAM_LOGIN.hint)
        self.instagram_set.setText("Replace" if login else "Set")
        self.instagram_remove.setVisible(bool(login))

    def edit_instagram(self) -> None:
        dialog = InstagramLoginDialog(self.window())
        while dialog.exec():
            try:
                self.state.keys.set_login(INSTAGRAM_LOGIN.name, dialog.username.text(), dialog.password.text())
            except ValueError as exc:
                dialog.error.setText(str(exc))
                dialog.error.show()
                continue
            self.state.say("Instagram account saved to Windows Credential Manager.")
            break
        dialog.password.clear()
        self.refresh_keys()
        self.state.settings_changed.emit()

    def remove_instagram(self) -> None:
        self.state.keys.delete(INSTAGRAM_LOGIN.name)
        self.state.say("Instagram account removed.")
        self.refresh_keys()
        self.state.settings_changed.emit()

    def edit_key(self, spec: KeySpec) -> None:
        dialog = KeyDialog(self.window(), spec)
        while dialog.exec():
            try:
                self.state.keys.set(spec.name, dialog.value.text())
            except ValueError as exc:
                dialog.error.setText(str(exc))
                dialog.error.show()
                continue
            self.state.say(f"{spec.title} key saved to Windows Credential Manager.")
            break
        dialog.value.clear()
        self.refresh_keys()
        self.state.settings_changed.emit()

    def remove_key(self, spec: KeySpec) -> None:
        self.state.keys.delete(spec.name)
        self.state.say(f"{spec.title} key removed.")
        self.refresh_keys()
        self.state.settings_changed.emit()

    def check_tools(self) -> None:
        if not self.check_btn.isEnabled():
            return
        tools = [t for t in self.state.catalog.tools if t.launch.kind is LaunchKind.SUBPROCESS]
        # Files and pinned hashes are checked on a worker; the sqlite connection is GUI-thread only.
        switches = {t.active_setting: self.state.db.get_setting(t.active_setting, False) for t in tools if t.is_active}
        settings = SimpleNamespace(get_setting=lambda key, default=None: switches.get(key, default))
        self.check_btn.setEnabled(False)
        self.check_btn.setText(tr("Checking…"))

        def done(results, error) -> None:
            self.check_btn.setEnabled(True)
            self.check_btn.setText(tr("Check"))
            clear_layout(self.tools_list)
            if error is not None:
                self.state.say(f"The tool check failed: {error}. Check that envs\\ and bin\\ are readable, then retry.")
                return
            for tool, status in results:
                tone = "green" if status.status == "Installed" else "muted"
                text = label(f"{tool.name}: {status.status}", tone=tone if tone == "green" else None,
                             role=None if tone == "green" else "muted")
                text.setStyleSheet("font-size: 12px;")
                text.setToolTip(fix_hint(tool, status))
                self.tools_list.addWidget(text)

        run_in_background(lambda: [(t, availability(t, settings)) for t in tools], done)
