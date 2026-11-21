import copy

import pytest
from pydantic import ValidationError

from core.catalog import load_catalog
from core.manifest import Label, LaunchKind, ToolManifest

BASE = {
    "id": "example_tool",
    "name": "Example tool",
    "category": "usernames",
    "description": "Checks example_user on example.com.",
    "limitations": "Results are leads.",
    "official_url": "https://example.com/tool",
    "license": "MIT",
    "open_source": True,
    "labels": ["external", "passive"],
    "target_types": ["username"],
    "launch": {
        "kind": "subprocess",
        "venv": "envs/example_tool",
        "args": ["-m", "example_tool", "{username}", "--out", "{out_file}"],
    },
    "parser": "adapters.example_tool:parse",
    "review_date": "2026-10-01",
}


def make(**changes) -> dict:
    data = copy.deepcopy(BASE)
    for key, value in changes.items():
        if key.startswith("launch__"):
            data["launch"][key.removeprefix("launch__")] = value
        elif value is None and key in data:
            del data[key]
        else:
            data[key] = value
    return data


def test_valid_manifest():
    tool = ToolManifest.model_validate(make())
    assert tool.launch.kind is LaunchKind.SUBPROCESS
    assert tool.launch.placeholders() == {"username", "out_file"}
    assert tool.display_tags == ["external", "passive", "oss"]
    assert tool.monogram == "ET"
    assert tool.short_url == "example.com/tool"


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"launch__args": ["--user={username}"]}, "whole argument"),
        ({"launch__args": ["{username}{email}"]}, "whole argument"),
        ({"launch__args": ["{password}"]}, "unknown placeholder"),
        ({"launch__args": ["{email}"]}, "undeclared target types"),
        ({"launch__venv": "../outside"}, "under envs/"),
        ({"launch__venv": "C:/Windows/System32"}, "under envs/"),
        ({"launch__venv": None, "launch__executable": "tools/x.exe"}, "under bin/"),
        ({"launch__venv": None}, "need a venv"),
        ({"launch__venv": None, "launch__executable": "bin/x.bat", "launch__sha256": "0" * 64}, "an .exe"),
        ({"launch__venv": None, "launch__executable": "bin/x.cmd", "launch__sha256": "0" * 64}, "an .exe"),
        ({"launch__venv": None, "launch__executable": "bin/x.ps1", "launch__sha256": "0" * 64}, "an .exe"),
        ({"launch__venv": None, "launch__executable": "bin/x.exe"}, "pinned sha256"),
        ({"launch__venv": None, "launch__executable": "bin/x.exe", "launch__sha256": "0" * 64,
          "launch__tree": "bin/x_files"}, "together"),
        ({"launch__tree": "envs/x", "launch__tree_sha256": "0" * 64}, "under bin/"),
        ({"target_types": ["other"], "launch__args": ["{other}"]}, "unknown placeholder"),
        ({"launch__timeout_s": 0}, "greater than or equal"),
        ({"labels": ["passive"]}, "local or external"),
        ({"labels": ["local", "external"]}, "local or external"),
        ({"labels": ["external", "active"]}, "Settings switch"),
        ({"active_setting": "active.example"}, "only for tools labeled active"),
        ({"labels": ["external", "api_key"]}, "api_key label"),
        ({"api_key": "required"}, "api_key label"),
        ({"official_url": "http://example.com"}, "https"),
        ({"official_url": "javascript:alert(1)"}, "https"),
        ({"id": "Bad-ID"}, "lowercase"),
        ({"parser": "os:system"}, "adapters."),
        ({"shell": True}, "Extra inputs"),
        ({"limitations": ""}, "at least 1"),
    ],
)
def test_unsafe_or_inconsistent_manifests_are_rejected(changes, message):
    with pytest.raises(ValidationError) as info:
        ToolManifest.model_validate(make(**changes))
    assert message in str(info.value)


def test_browser_tools_cannot_carry_args():
    with pytest.raises(ValidationError):
        ToolManifest.model_validate(make(launch={"kind": "browser", "args": ["{username}"]}))


def test_active_tool_with_switch_is_valid():
    tool = ToolManifest.model_validate(
        make(labels=["external", "active"], active_setting="active.example")
    )
    assert tool.is_active


def test_shipped_catalog_is_valid_and_complete():
    catalog = load_catalog()
    assert catalog.errors == []
    assert len(catalog.tools) >= 25
    for tool in catalog.tools:
        assert tool.official_url.startswith("https://")
        assert tool.limitations.strip()
        # A tool only gets an argument list once its adapter (parser) is integrated and tested.
        assert bool(tool.launch.args) == bool(tool.parser)
    assert {t.id for t in catalog.tools if t.launch.args} >= {"sherlock", "exiftool"}
    actives = {t.id for t in catalog.tools if Label.ACTIVE in t.labels}
    assert actives == {"holehe", "wafw00f", "dnsrecon_axfr", "ignorant"}
