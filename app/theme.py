"""Loads app/theme.qss: resolves @tokens, applies the stylesheet and palette.

QSS has no variables, so theme.qss starts with a token block; this module
substitutes the tokens and exposes them to Python (custom-painted widgets).
"""

from __future__ import annotations

import re
from pathlib import Path

from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

QSS_PATH = Path(__file__).with_name("theme.qss")
ASSETS_DIR = Path(__file__).with_name("assets")

_TOKEN_BLOCK = re.compile(r"/\*\s*@tokens(.*?)\*/", re.S)
_TOKEN_DEF = re.compile(r"^@([\w-]+)\s*:\s*(.+?);\s*$", re.M)
_TOKEN_REF = re.compile(r"@([\w-]+)")
_RGBA = re.compile(r"rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)")
FONT_TOKENS = ("sans", "mono", "icons")

#: Resolved tokens, filled by apply_theme() (or lazily by tokens()).
_tokens: dict[str, str] = {}


def parse_tokens(text: str) -> dict[str, str]:
    block = _TOKEN_BLOCK.search(text)
    if not block:
        raise ValueError("theme.qss has no /* @tokens ... */ block")
    return {name: value.strip() for name, value in _TOKEN_DEF.findall(block.group(1))}


def first_installed_family(value: str) -> str:
    """'"A", "B"' -> the first family Qt can find (or the first listed)."""
    families = [f.strip().strip('"') for f in value.split(",") if f.strip()]
    installed = set(QFontDatabase.families())
    for family in families:
        if family in installed:
            return family
    return families[0]


def build_stylesheet(text: str, tokens: dict[str, str]) -> str:
    body = _TOKEN_BLOCK.sub("", text, count=1)

    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in tokens:
            raise KeyError(f"theme.qss uses undefined token @{name}")
        value = tokens[name]
        return f'"{value}"' if name in FONT_TOKENS else value

    return _TOKEN_REF.sub(replace, body)


def load_tokens() -> dict[str, str]:
    tokens = parse_tokens(QSS_PATH.read_text(encoding="utf-8"))
    for name in FONT_TOKENS:
        tokens[name] = first_installed_family(tokens[name])
    tokens["assets"] = ASSETS_DIR.as_posix()
    return tokens


FONTS_DIR = ASSETS_DIR / "fonts"
_fonts_loaded = False


def load_bundled_fonts() -> None:
    """Register the bundled JetBrains Mono TTFs (OFL) so the mono token resolves without an install."""
    global _fonts_loaded
    if _fonts_loaded or QGuiApplication.instance() is None:
        return
    for path in sorted(FONTS_DIR.glob("*.ttf")):
        QFontDatabase.addApplicationFont(str(path))
    _fonts_loaded = True


def tokens() -> dict[str, str]:
    if not _tokens:
        load_bundled_fonts()
        _tokens.update(load_tokens())
    return _tokens


def color(name: str) -> QColor:
    value = tokens()[name]
    match = _RGBA.fullmatch(value)
    if match:
        r, g, b, a = (int(v) for v in match.groups())
        return QColor(r, g, b, a)
    return QColor(value)


def font(token: str = "sans", pixel_size: int = 13, weight: QFont.Weight = QFont.Weight.Normal) -> QFont:
    f = QFont(tokens()[token])
    f.setPixelSize(pixel_size)
    f.setWeight(weight)
    f.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    return f


def apply_theme(app: QApplication) -> dict[str, str]:
    toks = tokens()
    app.setStyle("Fusion")  # the native Windows 11 style ignores parts of QSS
    app.setFont(font("sans", 13))

    palette = QPalette()
    roles = {
        QPalette.ColorRole.Window: "win",
        QPalette.ColorRole.Base: "surface2",
        QPalette.ColorRole.AlternateBase: "surface",
        QPalette.ColorRole.Button: "surface2",
        QPalette.ColorRole.Text: "text",
        QPalette.ColorRole.WindowText: "text",
        QPalette.ColorRole.ButtonText: "text",
        QPalette.ColorRole.PlaceholderText: "dim",
        QPalette.ColorRole.Highlight: "accent-d",
        QPalette.ColorRole.HighlightedText: "text",
        QPalette.ColorRole.ToolTipBase: "surface2",
        QPalette.ColorRole.ToolTipText: "text",
        QPalette.ColorRole.Link: "accent",
    }
    for role, token in roles.items():
        palette.setColor(role, color(token))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, color("dim"))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, color("dim"))
    app.setPalette(palette)

    app.setStyleSheet(build_stylesheet(QSS_PATH.read_text(encoding="utf-8"), toks))
    return toks
