"""Packaging checks: the self-check entry point and what must never be bundled or committed."""

from __future__ import annotations

import json
import subprocess

from app.__main__ import self_check
from core.paths import PROJECT_ROOT


def test_self_check_reports_a_complete_build(tmp_path):
    report = tmp_path / "check.json"
    assert self_check(str(report)) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["tools"] >= 25 and data["manifest_errors"] == []
    assert len(data["modules"]) >= 25
    assert data["exiftool"] == "ok (hash verified)" or "not installed" in data["exiftool"]
    assert data["theme"] is True


def test_spec_does_not_bundle_tools_or_case_data():
    spec = (PROJECT_ROOT / "nightglass.spec").read_text(encoding="utf-8")
    datas = spec.split("datas=")[1].split("]")[0]
    for forbidden in ("envs", "cases", "bin", "tools", ".db"):
        assert forbidden not in datas


def test_gitignore_keeps_private_data_out():
    ignored = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").split()
    for pattern in ("cases/", "evidence/", "reports/", "logs/", "envs/", "*.db", ".env", "bin/*.exe", "dist/", "*.enc", "crash.log"):
        assert pattern in ignored
    tracked = subprocess.run(["git", "ls-files"], cwd=PROJECT_ROOT, capture_output=True, text=True).stdout.split()
    assert not [f for f in tracked if f.startswith(("cases/", "envs/", "dist/", "build/")) or f.endswith(".db")]


def test_garbage_collection_stays_on_the_main_thread(qapp):
    import gc

    from app.__main__ import _collect_on_main_thread

    _collect_on_main_thread(qapp)
    try:
        assert not gc.isenabled()
    finally:
        gc.enable()
