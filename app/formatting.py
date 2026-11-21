"""Human-readable times for the UI. Stored times are UTC; display is local."""

from __future__ import annotations

from datetime import datetime


def _local(dt: datetime) -> datetime:
    return dt.astimezone()


def clock_time(dt: datetime) -> str:
    return _local(dt).strftime("%H:%M")


def long_datetime(dt: datetime) -> str:
    """Oct 29, 2026 · 22:58"""
    local = _local(dt)
    return f"{local.strftime('%b')} {local.day}, {local.year} · {local.strftime('%H:%M')}"


def short_datetime(dt: datetime) -> str:
    """Oct 29, 21:58"""
    local = _local(dt)
    return f"{local.strftime('%b')} {local.day}, {local.strftime('%H:%M')}"


def relative(dt: datetime, now: datetime | None = None) -> str:
    """12 min ago · 3 h ago · Yesterday · Oct 24"""
    local = _local(dt)
    current = _local(now) if now else datetime.now().astimezone()
    seconds = (current - local).total_seconds()
    if seconds < 60:
        return "Just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    days = (current.date() - local.date()).days
    if days == 0:
        return f"{int(seconds // 3600)} h ago"
    if days == 1:
        return "Yesterday"
    label = f"{local.strftime('%b')} {local.day}"
    return label if local.year == current.year else f"{label}, {local.year}"


def greeting(now: datetime | None = None) -> str:
    hour = (now or datetime.now()).hour
    if 5 <= hour < 12:
        return "Good morning"
    if 12 <= hour < 18:
        return "Good afternoon"
    return "Good evening"
