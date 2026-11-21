"""Design system: the live tokens and components from app/theme.qss."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QPushButton, QWidget

from app import icons, theme
from app.widgets import Card, Screen, StatusDot, ToggleSwitch, button, hbox, label, tag, vbox

SURFACES = [("Window", "win"), ("Sidebar", "sidebar"), ("Surface", "surface"), ("Raised", "surface2"),
            ("Hover", "surface3"), ("Border", "border"), ("Border strong", "border2"), ("Console", "console")]
ACCENTS = [("Accent", "accent"), ("API key", "violet"), ("Local", "green"), ("External", "amber"),
           ("Passive", "blue"), ("Active", "red"), ("Text", "text"), ("Muted", "muted")]


def swatch(name: str, token: str) -> QWidget:
    chip = QFrame()
    chip.setFixedHeight(56)
    chip.setStyleSheet(f"background: {theme.tokens()[token]}; border: 1px solid {theme.tokens()['border']}; "
                       "border-radius: 8px;")
    code = label(theme.tokens()[token], "hint", mono=True, selectable=True)
    holder = QWidget()
    holder.setLayout(vbox(chip, label(name, "meta"), code, spacing=4))
    return holder


class DesignScreen(Screen):
    title = "Design System"

    def __init__(self):
        super().__init__()
        self.make_header("Design system", "Tokens and components used across Nightglass")

        brand = Card(padding=(16, 16, 16, 16))
        lockup = QLabel()
        lockup.setPixmap(icons.lockup(64))
        lockup.setAccessibleName("Nightglass")
        tagline = label("The faceted night owl: the watcher that sees in the dark. Amber eyes are the one warm "
                        "signal on a cold green-and-black palette. Brand files: docs/brand.", "muted", wrap=True)
        tile = QLabel()
        tile.setPixmap(icons.app_tile(64))
        tile.setToolTip("nightglass.ico · window and taskbar")
        row = hbox(lockup, spacing=24)
        row.addLayout(vbox(None, tagline, None, spacing=4), 1)
        row.addWidget(tile)
        brand.body_layout.addLayout(row)
        self.layout_.addWidget(brand)

        colors = QGridLayout()
        colors.setSpacing(14)
        for col, (title, items) in enumerate((("Surfaces", SURFACES), ("Accents & labels", ACCENTS))):
            card = Card(title)
            grid = QGridLayout()
            grid.setSpacing(12)
            for index, (swatch_name, token) in enumerate(items):
                grid.addWidget(swatch(swatch_name, token), index // 4, index % 4)
            card.body_layout.addLayout(grid)
            colors.addWidget(card, 0, col, Qt.AlignmentFlag.AlignTop)
        self.layout_.addLayout(colors)

        type_card = Card("Type")
        samples = [("Heading 20 / Semibold", "font-size: 20px; font-weight: 600;"),
                   ("Section 14 / Semibold", "font-size: 14px; font-weight: 600;"),
                   (f"Body 13 / Regular · {theme.tokens()['sans']}", "font-size: 13px;")]
        for text, style in samples:
            sample = label(text)
            sample.setStyleSheet(style)
            type_card.body_layout.addWidget(sample)
        type_card.body_layout.addWidget(label(f"Mono 12 · {theme.tokens()['mono']} — hashes, URLs, console", mono=True))
        type_card.body_layout.addWidget(label("Hint 11 / Dim", "hint"))

        components = Card("Components")
        components.body_layout.addLayout(hbox(button("Primary", "primary"), button("Secondary"),
                                              button("Ghost", "ghost"), button("Danger", "danger"), None))
        components.body_layout.addLayout(hbox(*[tag(k) for k in ("local", "external", "passive", "active",
                                                                  "api_key", "oss")], None, spacing=6))
        components.body_layout.addLayout(hbox(StatusDot("Lead", "lead"), StatusDot("Verified", "verified"),
                                              StatusDot("Uncertain", "uncertain"), StatusDot("Rejected", "rejected"),
                                              None, spacing=14))
        chip_on, chip_off = QPushButton("Chip on"), QPushButton("Chip")
        for chip, on in ((chip_on, True), (chip_off, False)):
            chip.setProperty("chip", True)
            chip.setCheckable(True)
            chip.setChecked(on)
        components.body_layout.addLayout(hbox(ToggleSwitch(True), ToggleSwitch(False), ToggleSwitch(True, danger=True),
                                              chip_on, chip_off, None, spacing=10))
        lower = QGridLayout()
        lower.setSpacing(14)
        lower.addWidget(type_card, 0, 0, Qt.AlignmentFlag.AlignTop)
        lower.addWidget(components, 0, 1, Qt.AlignmentFlag.AlignTop)
        lower.setColumnStretch(0, 1)
        lower.setColumnStretch(1, 1)
        self.layout_.addLayout(lower)
        self.layout_.addStretch(1)
