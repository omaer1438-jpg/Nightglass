"""SVG icons from the prototype's sprite, rendered in any theme color."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QGuiApplication, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from app import theme

_STROKE = 'fill="none" stroke="{c}" stroke-width="{w}"'

# name -> (attributes, inner svg). Paths copied from the prototype <symbol>s.
_ICONS: dict[str, tuple[str, str]] = {
    "dash": (_STROKE, '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>'),
    "case": (_STROKE, '<path d="M3 7h18v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M3 12h18"/>'),
    "plus": (_STROKE.replace("{w}", "2"), '<path d="M12 5v14M5 12h14"/>'),
    "mod": (_STROKE, '<path d="M4 17l6-6-6-6"/><path d="M12 19h8"/>'),
    "lib": (_STROKE, '<path d="M4 4h4v16H4zM10 4h4v16h-4z"/><path d="M16 5l3.5-1 3 15.5-3.5 1z"/>'),
    "rep": (_STROKE, '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>'),
    "set": (_STROKE, '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'),
    "ds": (_STROKE, '<circle cx="13.5" cy="6.5" r="2.5"/><circle cx="6.5" cy="12" r="2.5"/><circle cx="17.5" cy="15.5" r="2.5"/><path d="M12 22a10 10 0 1 1 10-10"/>'),
    "search": (_STROKE.replace("{w}", "2"), '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>'),
    "user": (_STROKE, '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>'),
    "mail": (_STROKE, '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>'),
    "phone": (_STROKE, '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>'),
    "pin": (_STROKE, '<path d="M12 22s7-6.2 7-12a7 7 0 0 0-14 0c0 5.8 7 12 7 12z"/><circle cx="12" cy="10" r="2.5"/>'),
    "globe": (_STROKE, '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>'),
    "lock": (_STROKE, '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
    "head": (_STROKE, '<path d="M4 6h16M4 12h10M4 18h7"/>'),
    "shield": (_STROKE, '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'),
    "img": (_STROKE, '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="M21 15l-5-5L5 21"/>'),
    "warn": (_STROKE, '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>'),
    "info": (_STROKE, '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'),
    "play": ('fill="{c}"', '<path d="M7 4v16l13-8z"/>'),
    "ext": (_STROKE, '<path d="M14 3h7v7M10 14L21 3M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"/>'),
    "down": (_STROKE, '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>'),
    "check": (_STROKE.replace("{w}", "3"), '<path d="M5 12l5 5L20 7"/>'),
    "clip": (_STROKE, '<path d="M21 11l-8.5 8.5a5 5 0 0 1-7-7L14 4a3.5 3.5 0 0 1 5 5l-8.5 8.5a2 2 0 0 1-3-3L15 7"/>'),
    "rev": (_STROKE, '<path d="M3 12a9 9 0 0 1 15.5-6.2L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15.5 6.2L3 16"/><path d="M3 21v-5h5"/>'),
    "dns": (_STROKE, '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>'),
    "tree": (_STROKE, '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-3h14v3"/>'),
    "cpu": (_STROKE, '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>'),
    "git": (_STROKE, '<circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="9" r="2.5"/><path d="M6 8.5v7M18 11.5c0 4-6 3-10.5 5"/>'),
    "port": (_STROKE, '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>'),
    "filter": (_STROKE, '<path d="M3 5h18l-7 8v6l-4 2v-8z"/>'),
    "folder": (_STROKE, '<path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'),
}

LOGO_DIR = Path(__file__).with_name("assets") / "logo"
ICO_PATH = Path(__file__).with_name("assets") / "nightglass.ico"
#: Brand guide: the full mark at 32 px and up, the small-icon file below that.
MARK = LOGO_DIR / "nightglass-mark.svg"
MARK_SMALL = LOGO_DIR / "nightglass-app-icon-small.svg"
APP_ICON = LOGO_DIR / "nightglass-app-icon.svg"
LOCKUP = LOGO_DIR / "nightglass-lockup-horizontal.svg"  # primary lockup, transparent


def _scale() -> float:
    screen = QGuiApplication.primaryScreen()
    return max(2.0, screen.devicePixelRatio() if screen else 1.0)


def _render(svg: str, size: int) -> QPixmap:
    scale = _scale()
    pixmap = QPixmap(int(size * scale), int(size * scale))
    pixmap.fill(Qt.GlobalColor.transparent)
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, pixmap.width(), pixmap.height()))
    painter.end()
    pixmap.setDevicePixelRatio(scale)
    return pixmap


@lru_cache(maxsize=512)
def pixmap(name: str, color_token: str = "muted", size: int = 16) -> QPixmap:
    attrs, body = _ICONS[name]
    color = theme.color(color_token).name()
    attrs = attrs.replace("{c}", color).replace("{w}", "1.8")
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" {attrs}>{body}</svg>'
    return _render(svg, size)


def icon(name: str, color_token: str = "muted", on_token: str | None = None, size: int = 16) -> QIcon:
    """Icon tinted with a theme color; `on_token` tints the checked/hover state."""
    result = QIcon()
    result.addPixmap(pixmap(name, color_token, size), QIcon.Mode.Normal, QIcon.State.Off)
    result.addPixmap(pixmap(name, "dim", size), QIcon.Mode.Disabled, QIcon.State.Off)
    if on_token:
        result.addPixmap(pixmap(name, on_token, size), QIcon.Mode.Normal, QIcon.State.On)
        result.addPixmap(pixmap(name, on_token, size), QIcon.Mode.Active, QIcon.State.Off)
        result.addPixmap(pixmap(name, on_token, size), QIcon.Mode.Active, QIcon.State.On)
    return result


def _render_file(path: Path, height: int) -> QPixmap:
    """Render a brand SVG at the given height, keeping its aspect ratio."""
    renderer = QSvgRenderer(str(path))
    box = renderer.viewBoxF()
    width = height * box.width() / box.height()
    scale = _scale()
    pixmap = QPixmap(int(round(width * scale)), int(round(height * scale)))
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, pixmap.width(), pixmap.height()))
    painter.end()
    pixmap.setDevicePixelRatio(scale)
    return pixmap


@lru_cache(maxsize=16)
def logo(size: int = 28) -> QPixmap:
    """The owl mark (small-icon file below 32 px, as the brand guide asks)."""
    return _render_file(MARK_SMALL if size < 32 else MARK, size)


@lru_cache(maxsize=4)
def app_tile(size: int = 64) -> QPixmap:
    return _render_file(APP_ICON, size)


@lru_cache(maxsize=4)
def lockup(height: int = 26) -> QPixmap:
    """Mark + outlined wordmark (the wordmark is never retyped)."""
    return _render_file(LOCKUP, height)


def app_icon() -> QIcon:
    """Window and taskbar icon: the brand nightglass.ico."""
    return QIcon(str(ICO_PATH))
