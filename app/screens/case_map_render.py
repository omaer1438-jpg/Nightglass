"""Case Map drawing: the investigation board scene, its cards and strings, thumbnails and PNG/SVG export.

Shared by the live view (app/screens/case_map.py) and report exports, so both look the same.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QLineF, QPointF, QRect, QRectF, QSize, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QImage,
    QImageReader,
    QPainter,
    QPainterPath,
    QPainterPathStroker,
    QPen,
    QPixmap,
    QPolygonF,
)
from PySide6.QtSvg import QSvgGenerator
from PySide6.QtWidgets import QGraphicsItem, QGraphicsScene

from app import icons, theme
from core.casemap import (EDGE_STYLE, Board, Edge, Graph, MapFilter, Node, apply_filter, bridge_edges, edge_tone,
                          layout)

CARD = (190.0, 96.0)
CASE_CARD = (240.0, 120.0)
GRID = 32
FULL_EXPORT_MAX = 60      # exports draw full cards up to this many nodes
MAX_EXPORT_HEIGHT = 8000
FOCUS_NODE_OPACITY, FOCUS_EDGE_OPACITY = 0.18, 0.08  # focus mode: what lies outside the selected neighbourhood
CURVE_SEGMENTS = 12     # strings are drawn as this many straight pieces
STRAIGHT_ABOVE = 400    # more strings than this on screen: straight ones below zoom 0.6
MAX_LABELS = 120        # string labels drawn at once (zoom >= 1.4)

STATUS_TOKEN = {"lead": "amber", "verified": "green", "uncertain": "blue", "rejected": "dim", "info": "muted"}
TONE_TOKEN = {"lead": "amber", "verified": "green", "rejected": "dim", "neutral": "border2"}
PEN_STYLE = {"solid": Qt.PenStyle.SolidLine, "dash": Qt.PenStyle.DashLine, "dot": Qt.PenStyle.DotLine}
KIND_LABEL = {"case": "CASE", "target": "TARGET", "finding": "FINDING", "source": "SOURCE",
              "evidence": "EVIDENCE", "note": "NOTE", "value": "SHARED"}
KIND_ICON = {"case": "case", "finding": "search", "source": "mod", "evidence": "img", "note": "head",
             "value": "tree"}
SUBTYPE_ICON = {"username": "user", "email": "mail", "phone": "phone", "ip": "port", "domain": "globe",
                "url": "ext", "file": "clip", "profile": "user", "account": "user", "host": "dns",
                "certificate": "shield", "metadata": "img", "record": "rep"}


def lod_for(zoom: float) -> str:
    """Level of detail for a zoom factor: pin dots far out, one-line chips in between, full cards close up."""
    if zoom < 0.35:
        return "pin"
    if zoom < 0.8:
        return "compact"
    return "full"


def separate(positions: dict, movable: set, iterations: int = 80, gap: float = 18.0) -> dict:
    """Push overlapping cards apart (the force layout spaces centres, not 190x96 rectangles).
    Only `movable` keys move; pure Python on a grid, so it may run on a worker thread."""
    pos = {k: [float(x), float(y)] for k, (x, y) in positions.items()}
    half = {k: ((CASE_CARD if k == "case" else CARD)[0] / 2, (CASE_CARD if k == "case" else CARD)[1] / 2) for k in pos}
    order = {k: i for i, k in enumerate(pos)}
    cell = CASE_CARD[0] + gap
    if pos and len(movable & pos.keys()) >= 0.8 * len(pos):
        # Mostly a fresh layout: first spread it to the area the cards need, then fix what still overlaps.
        radius = max(math.hypot(x, y) for x, y in pos.values()) or 1.0
        need = len(pos) * (CARD[0] + gap) * (CARD[1] + gap) * 1.5
        scale = math.sqrt(need / (math.pi * radius * radius))
        if scale > 1:
            for k in movable & pos.keys():
                pos[k][0] *= scale
                pos[k][1] *= scale
    for _ in range(iterations):
        grid: dict = {}
        for k, (x, y) in pos.items():
            grid.setdefault((int(x // cell), int(y // cell)), []).append(k)
        moved = False
        for k in movable:
            if k not in pos:
                continue
            x, y = pos[k]
            cx, cy = int(x // cell), int(y // cell)
            for gx in (cx - 1, cx, cx + 1):
                for gy in (cy - 1, cy, cy + 1):
                    for o in grid.get((gx, gy), ()):
                        if o == k:
                            continue
                        dx, dy = pos[k][0] - pos[o][0], pos[k][1] - pos[o][1]
                        ox = half[k][0] + half[o][0] + gap - abs(dx)
                        oy = half[k][1] + half[o][1] + gap - abs(dy)
                        if ox <= 0 or oy <= 0:
                            continue
                        both = o in movable
                        share = 0.5 if both else 1.0
                        tie = 1.0 if order[k] > order[o] else -1.0
                        axis, overlap, d = (0, ox, dx) if ox < oy else (1, oy, dy)
                        step = (1.0 if d > 0 else -1.0 if d < 0 else tie) * overlap * share
                        pos[k][axis] += step
                        if both:
                            pos[o][axis] -= step
                        moved = True
        if not moved:
            break
    return {k: (round(x, 1), round(y, 1)) for k, (x, y) in pos.items()}


@lru_cache(maxsize=None)
def _font(token: str, size: int, weight: int = 400) -> QFont:
    f = theme.font(token, size, QFont.Weight(weight))
    if token == "sans" and weight >= 700:
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.6)
    return f


@lru_cache(maxsize=None)
def _c(token: str) -> QColor:
    return theme.color(token)


def _draw_ltr(painter: QPainter, at: QPointF, text: str) -> None:
    """Values (+1 555 0100, URLs, hashes) read left to right even in the Arabic, right-to-left UI."""
    direction = painter.layoutDirection()
    painter.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
    painter.drawText(at, text)
    painter.setLayoutDirection(direction)


def wrap_lines(fm: QFontMetrics, text: str, width: int, max_lines: int) -> list[str]:
    """Greedy word wrap into at most max_lines; the last line is elided."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for index, word in enumerate(words):
        trial = f"{current} {word}".strip()
        if not current or fm.horizontalAdvance(trial) <= width:
            current = trial
            continue
        lines.append(current)
        if len(lines) == max_lines - 1:
            current = " ".join(words[index:])
            break
        current = word
    if current:
        lines.append(current)
    return [fm.elidedText(line, Qt.TextElideMode.ElideRight, width) for line in lines[:max_lines]]


# ---------------------------------------------------------------- thumbnails

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
MAX_THUMB_SOURCE = 20 * 1024 * 1024
MAX_THUMBS = 256
_thumbs: dict[str, QPixmap | None] = {}


def thumbnail(path: str | Path, evidence_dir: str | Path) -> QPixmap | None:
    """Small preview of an evidence image; only regular image files inside the case's evidence folder."""
    key = f"{path}|{evidence_dir}"
    if key in _thumbs:
        return _thumbs[key]
    result = None
    try:
        file = Path(path).resolve()
        if (file.suffix.lower() in IMAGE_EXT and file.is_file() and file.is_relative_to(Path(evidence_dir).resolve())
                and file.stat().st_size <= MAX_THUMB_SOURCE):
            reader = QImageReader(str(file))
            reader.setAutoTransform(True)
            size = reader.size()
            if size.isValid():
                reader.setScaledSize(size.scaled(64, 48, Qt.AspectRatioMode.KeepAspectRatio))
            image = reader.read()
            if not image.isNull():
                result = QPixmap.fromImage(image)
    except (OSError, ValueError):
        result = None
    if len(_thumbs) >= MAX_THUMBS:
        _thumbs.clear()  # shortcut: drop-all bound instead of LRU; fine while a case holds a few hundred images
    _thumbs[key] = result
    return result


# ---------------------------------------------------------------- cards


class NodeItem(QGraphicsItem):
    """A pinned card. Position is the card centre; strings attach to the pin at the top edge."""

    def __init__(self, node: Node, count: int = 0, redact: Callable[[str], str] | None = None,
                 thumb: Callable[[Node], QPixmap | None] | None = None):
        super().__init__()
        self.node = node
        self.key = node.key
        self.edges: list[EdgeItem] = []
        self.locked = False
        self.matched = False
        self.hovered = False
        self.focus_dim = False
        self._thumb_fn = thumb
        self._thumb: QPixmap | None | bool = False  # False = not loaded yet
        self.w, self.h = CASE_CARD if node.kind == "case" else CARD
        self._rect = QRectF(-self.w / 2, -self.h / 2, self.w, self.h)
        self._bounds = self._rect.adjusted(-6, -12, 6, 6)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.OpenHandCursor)
        self.base_opacity = 0.55 if node.status == "rejected" else 1.0
        self.setOpacity(self.base_opacity)
        clean = redact or (lambda s: s)
        self.status_token = STATUS_TOKEN.get(node.status, "muted") if node.kind == "finding" else "muted"
        kind = KIND_LABEL.get(node.kind, node.kind.upper())
        if node.subtype and node.kind in ("target", "finding", "value"):
            kind = f"{kind} · {node.subtype.upper()}"
        self.icon_name = SUBTYPE_ICON.get(node.subtype, KIND_ICON.get(node.kind, "search")) \
            if node.kind in ("target", "finding") else KIND_ICON.get(node.kind, "search")
        inner = int(self.w - 20)
        has_thumb = node.kind == "evidence" and thumb is not None and Path(node.detail).suffix.lower() in IMAGE_EXT
        text_w = inner - 74 if has_thumb else inner
        sans_title = QFontMetrics(_font("sans", 15 if node.kind == "case" else 12, 600))
        self.type_text = QFontMetrics(_font("sans", 9, 700)).elidedText(kind, Qt.TextElideMode.ElideRight, inner - 18)
        label = clean(node.label or "")
        if node.kind == "note":
            self.title_lines = wrap_lines(QFontMetrics(_font("sans", 12)), clean(node.value or label), inner, 4)
        else:
            self.title_lines = wrap_lines(sans_title, label, text_w, 2)
        self.value_text = QFontMetrics(_font("mono", 11)).elidedText(
            clean(node.value or ""), Qt.TextElideMode.ElideMiddle, text_w)
        self.compact_lines = wrap_lines(QFontMetrics(_font("sans", 20, 600)),
                                        clean(node.value) if node.kind == "note" else label, inner - 4, 2)
        if node.kind == "finding":
            self.footer_left = node.status.capitalize() if node.status else ""
            self.footer_right = QFontMetrics(_font("sans", 10)).elidedText(
                node.module or "", Qt.TextElideMode.ElideRight, inner // 2)
        elif node.kind == "note":
            self.footer_left = self.footer_right = ""
        else:
            self.footer_left = ""
            self.footer_right = clean(node.detail) if node.kind in ("evidence", "value") else f"{count} linked"
        self.setToolTip(label if node.kind != "note" else "")

    def set_note(self, node: Node) -> None:
        """Re-wrap a sticky note being edited, without rebuilding the whole board."""
        self.node = node
        inner = int(self.w - 20)
        text = node.value or node.label
        self.title_lines = wrap_lines(QFontMetrics(_font("sans", 12)), text, inner, 4)
        self.compact_lines = wrap_lines(QFontMetrics(_font("sans", 20, 600)), text, inner - 4, 2)
        self.update()

    # geometry
    def boundingRect(self) -> QRectF:
        return self._bounds

    def pin_pos(self) -> QPointF:
        return self.pos() + QPointF(0, -self.h / 2)

    def pin_hit(self, scene_pos: QPointF, radius: float) -> bool:
        return QLineF(scene_pos, self.pin_pos()).length() <= radius

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self.edges:
                edge.adjust()
        return super().itemChange(change, value)

    def set_locked(self, locked: bool) -> None:
        self.locked = locked
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, not locked)
        self.setCursor(Qt.CursorShape.ArrowCursor if locked else Qt.CursorShape.OpenHandCursor)
        self.update()

    def hoverEnterEvent(self, event) -> None:
        self.hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self.hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    # painting
    def lod(self, painter: QPainter) -> str:
        scene = self.scene()
        forced = getattr(scene, "force_lod", None)
        if forced:
            return forced
        level = lod_for(painter.worldTransform().m11())
        if (self.isSelected() or self.matched) and level == "pin":
            return "compact"
        return level

    def _border(self) -> QPen:
        if self.isSelected():
            return QPen(_c("accent"), 1.5)
        if self.matched:
            return QPen(_c("accent-d"), 1.5)
        if self.node.kind == "note":
            pen = QPen(_c("border-hover" if self.hovered else "dim"), 1, Qt.PenStyle.DashLine)
            return pen
        return QPen(_c("border-hover" if self.hovered else "border2"), 1)

    def _pin(self, painter: QPainter, at: QPointF, radius: float) -> None:
        painter.setPen(QPen(_c("win"), max(1.5, radius * 0.4)))
        painter.setBrush(_c(self.status_token))
        painter.drawEllipse(at, radius, radius)
        if self.locked:
            painter.setPen(QPen(_c(self.status_token), 1))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(at, radius + 3.5, radius + 3.5)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        level = self.lod(painter)
        r = self._rect
        pin = QPointF(0, r.top())
        if level == "pin":  # far out: only the pins, so the strings between them stay readable
            self._pin(painter, pin, min(40.0, 3.5 / max(painter.worldTransform().m11(), 0.01)))
            return
        if level == "compact":
            # Same card, fewer and bigger words: icon + title at 20px stays readable down to ~0.4 zoom.
            painter.setPen(self._border())
            painter.setBrush(_c("surface" if self.node.kind == "note" else "surface2"))
            painter.drawRoundedRect(r, 10, 10)
            if self.node.active and self.node.kind == "finding":
                painter.setPen(QPen(_c("red"), 3))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawRoundedRect(r.adjusted(-2, -2, 2, 2), 11, 11)
            painter.drawPixmap(QPointF(r.left() + 12, r.top() + 12), icons.pixmap(self.icon_name, "muted", 22))
            painter.setFont(_font("sans", 20, 600))
            painter.setPen(_c("dim" if self.node.status == "rejected" else "text"))
            for index, line in enumerate(self.compact_lines):
                painter.drawText(QPointF(r.left() + 12, r.top() + 58 + index * 24), line)
            self._pin(painter, pin, 6)
            return
        self._paint_full(painter, r)
        self._pin(painter, pin, 3.5)

    def _paint_full(self, painter: QPainter, r: QRectF) -> None:
        node = self.node
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(_c("surface" if node.kind == "note" else "surface2"))
        painter.setPen(self._border())
        painter.drawRoundedRect(r, 10, 10)
        if node.active and node.kind == "finding":
            painter.setPen(QPen(_c("red"), 2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(r.adjusted(-2, -2, 2, 2), 11, 11)
        left, top = r.left() + 10, r.top() + 12
        painter.drawPixmap(QPointF(left, top - 1), icons.pixmap(self.icon_name, "muted", 12))
        painter.setFont(_font("sans", 9, 700))
        painter.setPen(_c("muted"))
        painter.drawText(QRectF(left + 18, top - 2, r.width() - 46, 14), Qt.AlignmentFlag.AlignVCenter, self.type_text)
        if self.locked:
            painter.drawPixmap(QPointF(r.right() - 22, top - 1), icons.pixmap("lock", "muted", 11))
        thumb = self._thumbnail()
        if thumb is not None:
            painter.drawPixmap(QPointF(r.right() - 10 - thumb.width() / thumb.devicePixelRatio(), top + 18), thumb)
        y = top + 18
        if node.kind == "case":
            painter.setFont(_font("mono", 11))
            painter.setPen(_c("muted"))
            _draw_ltr(painter, QPointF(left, y + 10), self.value_text)
            y += 18
        title_size = 15 if node.kind == "case" else 12
        line_h = title_size + 4
        painter.setFont(_font("sans", title_size, 400 if node.kind == "note" else 600))
        painter.setPen(_c("dim" if node.status == "rejected" else "text"))
        for line in self.title_lines:
            painter.drawText(QPointF(left, y + title_size), line)
            y += line_h
        if node.kind not in ("note", "case") and self.value_text:
            painter.setFont(_font("mono", 11))
            painter.setPen(_c("dim"))
            _draw_ltr(painter, QPointF(left, max(y + 11, r.bottom() - 30)), self.value_text)  # below a 2-line title
        base = r.bottom() - 11
        if self.footer_left:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(_c(self.status_token))
            painter.drawEllipse(QPointF(left + 3, base - 4), 3, 3)
            painter.setFont(_font("sans", 10, 600))
            painter.setPen(_c(self.status_token))
            painter.drawText(QPointF(left + 11, base), self.footer_left)
        if self.footer_right:
            painter.setFont(_font("sans", 10))
            painter.setPen(_c("dim"))
            painter.drawText(QRectF(r.center().x(), base - 12, r.width() / 2 - 10, 16),
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, self.footer_right)

    def _thumbnail(self) -> QPixmap | None:
        if self._thumb_fn is None:
            return None
        if self._thumb is False:
            self._thumb = self._thumb_fn(self.node)  # lazy: first full-detail paint only
        return self._thumb or None


# ---------------------------------------------------------------- strings


class EdgeItem(QGraphicsItem):
    """One string's geometry, hover and click target. It paints nothing itself: the scene's EdgeLayer
    draws every string in a few batched paths (one Python paint call per string is too slow at 500+ cards)."""

    def __init__(self, edge: Edge, a: NodeItem, b: NodeItem, tone: str, redact: Callable[[str], str] | None = None):
        super().__init__()
        self.edge, self.a, self.b, self.tone = edge, a, b, tone
        self.label = (redact or (lambda s: s))(edge.label or "")
        self.label_text, self.label_box = "", None
        self.layer: EdgeLayer | None = None
        self.hovered = False
        self.focus_dim = False
        a.edges.append(self)
        b.edges.append(self)
        self.setZValue(-1)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemHasNoContents)
        self.setAcceptHoverEvents(True)
        analyst = edge.kind == "analyst"
        self.style = "dashdot" if analyst else EDGE_STYLE.get(edge.confidence, "solid")
        self.width = 0.8 if analyst else 1.4
        self.arrow = edge.directed and edge.kind in ("found_by", "via")
        self.path = QPainterPath()
        self._bounds = QRectF()
        self._shape: QPainterPath | None = None
        self.adjust()

    def adjust(self) -> None:
        self.prepareGeometryChange()
        p1, p2 = self.a.pin_pos(), self.b.pin_pos()
        length = QLineF(p1, p2).length()
        self.path = QPainterPath(p1)
        self.path.quadTo((p1 + p2) / 2 + QPointF(0, min(36.0, 0.1 * length)), p2)
        points = [self.path.pointAtPercent(t / CURVE_SEGMENTS) for t in range(CURVE_SEGMENTS + 1)]
        self.segments = [QLineF(points[i], points[i + 1]) for i in range(CURVE_SEGMENTS)]
        self.line = QLineF(p1, p2)
        self.mid = self.path.pointAtPercent(0.5)
        a = math.radians(-self.path.angleAtPercent(0.5))
        self.arrow_poly = QPolygonF([self.mid + QPointF(math.cos(a + s), math.sin(a + s)) * 6.0
                                     for s in (0.0, 2.6, -2.6, 0.0)])
        self._bounds = self.path.boundingRect().adjusted(-6, -6, 6, 6)
        self._shape = None  # stroked lazily: only hit tests need it
        if self.layer is not None:
            self.layer.update()

    def boundingRect(self) -> QRectF:
        return self._bounds

    def shape(self) -> QPainterPath:
        if self._shape is None:
            stroker = QPainterPathStroker()
            stroker.setWidth(10)
            self._shape = stroker.createStroke(self.path)
        return self._shape

    def paint(self, painter: QPainter, option, widget=None) -> None:
        pass

    def hoverEnterEvent(self, event) -> None:
        self.hovered = True
        if self.layer is not None:
            self.layer.set_hovered(self)

    def hoverLeaveEvent(self, event) -> None:
        self.hovered = False
        if self.layer is not None:
            self.layer.set_hovered(None)


def _edge_pen(edge: EdgeItem, extra: float = 0.0) -> QPen:
    style = Qt.PenStyle.DashDotLine if edge.style == "dashdot" else PEN_STYLE[edge.style]
    pen = QPen(_c(TONE_TOKEN.get(edge.tone, "border2")), edge.width + extra, style)
    pen.setCosmetic(True)
    return pen


class EdgeLayer(QGraphicsItem):
    """Draws every visible string in one paint call, grouped by pen into a few drawLines() calls.

    Curves are pre-flattened into short segments: stroking QPainterPaths costs ~25x more at 500+ cards.
    Busy boards (> STRAIGHT_ABOVE strings on screen) use straight strings below zoom 0.6.
    Arrowheads from zoom 0.6, labels on hover (zoom >= 0.6) and everywhere from 1.4."""

    def __init__(self, edges: list[EdgeItem]):
        super().__init__()
        self.edges = edges
        self.hovered: EdgeItem | None = None
        self.setZValue(-2)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemUsesExtendedStyleOption)
        self.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
        for edge in edges:
            edge.layer = self

    def boundingRect(self) -> QRectF:
        return QRectF(-1e6, -1e6, 2e6, 2e6)

    def invalidate(self) -> None:
        self.update()

    def set_hovered(self, edge: EdgeItem | None) -> None:
        self.hovered = edge
        self.update()

    def paint(self, painter: QPainter, option, widget=None) -> None:
        zoom = painter.worldTransform().m11()
        if getattr(self.scene(), "force_lod", None) == "full":
            zoom = max(zoom, 1.0)
        # exposedRect can be the whole (huge) layer; the painter viewport is what is really on screen
        area = painter.worldTransform().inverted()[0].mapRect(QRectF(painter.viewport())) & option.exposedRect
        shown = [e for e in self.edges if e.isVisible() and e._bounds.intersects(area)]
        curved = zoom >= 0.35 and (zoom >= 0.6 or len(shown) <= STRAIGHT_ABOVE)
        groups: dict = {}
        for e in shown:
            group = groups.setdefault((e.tone, e.style, e.width, e.focus_dim), (e, [], QPainterPath()))
            if curved:
                group[1].extend(e.segments)
            else:
                group[1].append(e.line)
            if e.arrow and zoom >= 0.6:
                group[2].addPolygon(e.arrow_poly)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, zoom >= 0.35)
        for (_tone, _style, _width, dim), (sample, lines, arrows) in groups.items():
            painter.setOpacity(FOCUS_EDGE_OPACITY if dim else 1.0)
            pen = _edge_pen(sample)
            painter.setPen(pen)
            painter.drawLines(lines)
            if not arrows.isEmpty():
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(pen.color())
                painter.drawPath(arrows)
        painter.setOpacity(1.0)
        hovered = self.hovered if self.hovered is not None and self.hovered.isVisible() and zoom >= 0.6 else None
        if hovered is not None:
            painter.setPen(_edge_pen(hovered, 1.0))
            painter.drawLines(hovered.segments)
        drawn = 0
        if zoom >= 1.4:
            for e in shown:
                if e.label and e is not hovered and area.contains(e.mid) and drawn < MAX_LABELS:
                    drawn += 1
                    self._paint_label(painter, e, zoom)
        if hovered is not None and hovered.label:
            self._paint_label(painter, hovered, zoom)

    def _paint_label(self, painter: QPainter, edge: EdgeItem, zoom: float) -> None:
        if edge.label_box is None:  # measured once per string
            fm = QFontMetrics(_font("sans", 10))
            edge.label_text = fm.elidedText(edge.label, Qt.TextElideMode.ElideRight, 220)
            width = fm.horizontalAdvance(edge.label_text)
            edge.label_box = QRectF(-width / 2 - 6, 8, width + 12, fm.height() + 4)
        painter.save()
        painter.setOpacity(FOCUS_EDGE_OPACITY if edge.focus_dim else 1.0)
        painter.translate(edge.mid)
        painter.scale(1 / zoom, 1 / zoom)  # labels stay 10px on screen
        painter.setPen(QPen(_c("border2"), 1))
        painter.setBrush(_c("surface"))
        painter.drawRoundedRect(edge.label_box, 5, 5)
        painter.setFont(_font("sans", 10))
        painter.setPen(_c("text" if edge.hovered else "muted"))
        painter.drawText(edge.label_box, Qt.AlignmentFlag.AlignCenter, edge.label_text)
        painter.restore()

# ---------------------------------------------------------------- scene


class MapScene(QGraphicsScene):
    """The board: dark background with a faint dot grid, cards and strings."""

    def __init__(self, graph: Graph, positions: dict, keys: set[str] | None = None, *, grid: bool = True,
                 force_lod: str | None = None, redact: Callable[[str], str] | None = None,
                 thumb: Callable[[Node], QPixmap | None] | None = None):
        super().__init__()
        self.grid = grid
        self.force_lod = force_lod
        self.setItemIndexMethod(QGraphicsScene.ItemIndexMethod.BspTreeIndex)
        self.nodes: dict[str, NodeItem] = {}
        self.edges: list[EdgeItem] = []
        keys = set(graph.nodes) if keys is None else keys
        for key, node in graph.nodes.items():
            if key not in keys:
                continue
            item = NodeItem(node, len(graph.adj.get(key, ())), redact, thumb)
            x, y = positions.get(key, (0.0, 0.0))
            item.setPos(x, y)
            self.addItem(item)
            self.nodes[key] = item
        for edge in graph.edges:
            a, b = self.nodes.get(edge.src), self.nodes.get(edge.dst)
            if a is None or b is None:
                continue
            item = EdgeItem(edge, a, b, edge_tone(edge, graph.nodes), redact)
            self.addItem(item)
            self.edges.append(item)
        self.layer = EdgeLayer(self.edges)
        self.addItem(self.layer)

    def add_edges(self, edges: list[Edge], nodes: dict[str, Node]) -> list[EdgeItem]:
        """Extra strings drawn for the current filter only (bridge_edges); undo with remove_edges."""
        items = []
        for edge in edges:
            a, b = self.nodes.get(edge.src), self.nodes.get(edge.dst)
            if a is not None and b is not None:
                item = EdgeItem(edge, a, b, edge_tone(edge, nodes))
                item.layer = self.layer
                self.addItem(item)
                self.edges.append(item)  # the layer draws from this same list
                items.append(item)
        self.layer.update()
        return items

    def remove_edges(self, items: list[EdgeItem]) -> None:
        if self.layer.hovered in items:
            self.layer.hovered = None
        for item in items:
            self.removeItem(item)
            item.a.edges.remove(item)
            item.b.edges.remove(item)
            self.edges.remove(item)
        self.layer.update()

    def cards_rect(self) -> QRectF:
        """Bounds of the cards only (the string layer is unbounded)."""
        rect = QRectF()
        for item in self.nodes.values():
            if item.isVisible():
                rect |= item.sceneBoundingRect()
        return rect if not rect.isNull() else QRectF(-200, -100, 400, 200)

    def drawBackground(self, painter: QPainter, rect: QRectF) -> None:
        painter.fillRect(rect, _c("win"))
        zoom = painter.worldTransform().m11()
        if not self.grid or zoom < 0.5:
            return
        left = math.floor(rect.left() / GRID) * GRID
        top = math.floor(rect.top() / GRID) * GRID
        points = [QPointF(x, y) for x in range(int(left), int(rect.right()) + 1, GRID)
                  for y in range(int(top), int(rect.bottom()) + 1, GRID)]
        pen = QPen(_c("border"), 2)
        pen.setCosmetic(True)
        painter.setPen(pen)
        painter.drawPoints(QPolygonF(points))


# ---------------------------------------------------------------- export


def _export_scene(graph: Graph, board: Board, filt: MapFilter | None, redact) -> tuple[MapScene, QRectF]:
    keys = apply_filter(graph, filt)[0] if filt is not None else set(graph.nodes)
    positions = dict(board.positions)
    if any(k not in positions for k in keys):
        positions = layout(graph, saved=board.positions, pinned=frozenset(board.pinned))
    # Shared groups whose centre card is filtered out still connect their visible members.
    graph = Graph(graph.nodes, graph.edges + bridge_edges(graph, keys), graph.adj, graph.stats)
    scene = MapScene(graph, positions, keys, grid=False,
                     force_lod="full" if len(keys) <= FULL_EXPORT_MAX else None, redact=redact)
    for key in board.pinned:
        if key in scene.nodes:
            scene.nodes[key].set_locked(True)
    rect = scene.cards_rect().adjusted(-40, -40, 40, 40)
    return scene, rect


def _write(data: bytes, path) -> bytes:
    if path is not None:
        Path(path).write_bytes(data)
    return data


def render_png(graph: Graph, board: Board, path=None, width: int = 1600, filt: MapFilter | None = None,
               redact: Callable[[str], str] | None = None) -> bytes:
    """The board as a PNG (no grid, no thumbnails). Height is capped at 8000 px."""
    scene, rect = _export_scene(graph, board, filt, redact)
    scale = min(width / rect.width(), 1.5, MAX_EXPORT_HEIGHT / rect.height())
    size = QSize(max(1, round(rect.width() * scale)), max(1, round(rect.height() * scale)))
    image = QImage(size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(_c("win"))
    painter = QPainter(image)
    painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing
                           | QPainter.RenderHint.SmoothPixmapTransform)
    scene.render(painter, QRectF(0, 0, size.width(), size.height()), rect)
    painter.end()
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    return _write(bytes(buffer.data()), path)


def render_svg(graph: Graph, board: Board, path=None, filt: MapFilter | None = None,
               redact: Callable[[str], str] | None = None) -> bytes:
    """The board as SVG at 1:1 scene scale."""
    scene, rect = _export_scene(graph, board, filt, redact)
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    generator = QSvgGenerator()
    generator.setOutputDevice(buffer)
    size = QSize(math.ceil(rect.width()), math.ceil(rect.height()))
    generator.setSize(size)
    generator.setViewBox(QRect(0, 0, size.width(), size.height()))
    generator.setTitle("Case map")
    generator.setDescription("Nightglass case map. Connections are leads until verified.")
    painter = QPainter(generator)
    painter.fillRect(QRectF(0, 0, size.width(), size.height()), QBrush(_c("win")))
    scene.render(painter, QRectF(0, 0, size.width(), size.height()), rect)
    painter.end()
    buffer.close()
    return _write(bytes(data), path)
