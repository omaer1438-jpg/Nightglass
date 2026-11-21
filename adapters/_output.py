"""Shared helpers for reading untrusted tool and provider output."""

from __future__ import annotations

import functools
import json

import pydantic

from core.findings import Confidence, Finding, ResultKind


def unexpected_output(source: str):
    """Decorator for a parser or a module's run(): malformed or wrong-shape data becomes one clear
    error ("Unexpected output from <source>") instead of a developer error such as AttributeError."""

    def wrap(fn):
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Unexpected output from {source}: it is not valid JSON.") from exc
            except (AttributeError, TypeError, KeyError, IndexError, pydantic.ValidationError) as exc:
                raise ValueError(f"Unexpected output from {source}: the data is not in the expected format.") from exc
        return inner
    return wrap


def stored_counts(limit: int, **totals: int) -> dict[str, int]:
    """Run counts that match what was stored, plus what was left out over the limit.
    stored_counts(2000, found=25517) -> {"found": 2000, "found_not_stored_(over_2000)": 23517}"""
    counts = {}
    for key, total in totals.items():
        counts[key] = min(total, limit)
        if total > limit:
            counts[f"{key}_not_stored_(over_{limit})"] = total - limit
    return counts


def unreachable(module: str, source: str, reason: str) -> Finding:
    """An Uncertain finding for a source that could not be checked, so "nothing found" and
    "nothing reachable" never look the same."""
    return Finding(module=module, title=f"{source}: not checked", value=reason, source=source,
                   confidence=Confidence.LOW, result=ResultKind.UNCERTAIN,
                   notes="This source could not be reached or answered with an error. Try again later.")
