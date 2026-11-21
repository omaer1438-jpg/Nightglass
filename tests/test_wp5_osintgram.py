"""WP5: Osintgram with the owner's own Instagram login. The login must never survive a run, only
target-focused commands may run, and nothing logs in to Instagram here: a fake program stands in for
Osintgram. Fake data only (example_user, example.com)."""

from __future__ import annotations

import json
import sys
import threading
import time

import pytest

import core.modules as modules
from adapters import osintgram
from core.catalog import Availability, load_catalog
from core.findings import ResultKind
from core.modules import discover, module_status
from core.runner import JobCancelled, ModuleContext
from core.secrets import INSTAGRAM_LOGIN, KeyStore, MemoryKeyring
from core.validation import TargetType

OWNER, PASSWORD = "example_owner", "fake pass phrase 42"
LOGIN = json.dumps({"username": OWNER, "password": PASSWORD})

# Stands in for Osintgram: checks the login file is there, leaves session/cookie files behind like a real
# login would, echoes the password once (it must be redacted), prints JSON lines, exits with argv[1].
FAKE = r"""
import json, pathlib, sys, time
ini = pathlib.Path("config/credentials.ini").read_text(encoding="utf-8")
assert "username = example_owner" in ini and "password = fake pass phrase 42" in ini, ini
pathlib.Path("config/instagrapi_session.json").write_text('{"cookies": "fake"}')
pathlib.Path("cookies.txt").write_text("fake cookie")
pathlib.Path("sub").mkdir()
pathlib.Path("sub/session.dat").write_text("fake session")
print("debug: logging in with fake pass phrase 42", flush=True)
if sys.argv[1] == "sleep":
    time.sleep(60)
print(json.dumps(dict(command="info", data=dict(full_name="Example User", follower_count=12, is_private=False,
      bio_links=[dict(title="site", url="https://example.com/")]))), flush=True)
print(json.dumps(dict(command="tagged", data=[dict(username="example_friend", full_name="Ex Friend", posts=2)])))
print(json.dumps(dict(command="hashtags", error="RequestLimitReachedError: limit")))
print(json.dumps(dict(command="fwersemail", data=["someone@example.com"])))
sys.exit(int(sys.argv[1]))
"""


@pytest.fixture
def fake_tool(monkeypatch):
    def fake_build(tool, kind, value, work_dir):
        assert tool.id == "osintgram" and TargetType(kind) is TargetType.USERNAME
        return sys.executable, ["-c", FAKE, fake_build.mode]
    fake_build.mode = "0"
    monkeypatch.setattr(osintgram, "build_command", fake_build)
    return fake_build


def context(work_dir, cancel=None, api_key=LOGIN):
    lines: list[str] = []
    ctx = ModuleContext(TargetType.USERNAME, "example_user", work_dir, lines.append, cancel or threading.Event(),
                        {"api_key": api_key})
    return ctx, lines


def assert_no_login_left(run_dir):
    assert not (run_dir / "config").exists()
    for path in run_dir.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert PASSWORD not in text, path
            assert not osintgram._SECRET_FILE.search(path.name), path


def test_successful_run_deletes_login_session_and_cookies(tmp_path, fake_tool):
    run_dir = tmp_path / "runs" / "r-0001"
    run_dir.mkdir(parents=True)
    ctx, lines = context(run_dir)
    findings = osintgram.run(ctx)
    assert_no_login_left(run_dir)
    assert all(PASSWORD not in line for line in lines)
    assert "[password]" in (run_dir / osintgram.RAW_FILE).read_text(encoding="utf-8")
    titles = {f.title: f for f in findings}
    assert titles["Instagram profile"].url == "https://www.instagram.com/example_user/"
    assert titles["Instagram: Name"].value == "Example User"
    assert titles["Tagged by @example_user: @example_friend"].result is ResultKind.FOUND
    assert titles["Osintgram hashtags: not checked"].result is ResultKind.UNCERTAIN
    assert not any("someone@example.com" in (f.value or "") for f in findings)  # not an allowed command
    assert all("proof" in f.notes for f in findings if f.result is ResultKind.FOUND)


def test_failed_run_still_deletes_the_login(tmp_path, fake_tool, monkeypatch):
    fake_tool.mode = "3"
    ctx, _ = context(tmp_path)
    osintgram.run(ctx)  # partial output is still read
    assert_no_login_left(tmp_path)

    def broken(*args, **kwargs):
        assert (tmp_path / "config" / "credentials.ini").is_file()
        raise OSError("could not start")
    monkeypatch.setattr(osintgram.subprocess, "Popen", broken)
    with pytest.raises(OSError):
        osintgram.run(context(tmp_path)[0])
    assert_no_login_left(tmp_path)


def test_cancelled_run_kills_the_tool_and_deletes_the_login(tmp_path, fake_tool):
    fake_tool.mode = "sleep"
    cancel = threading.Event()
    threading.Timer(1.5, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(JobCancelled):
        osintgram.run(context(tmp_path, cancel)[0])
    assert time.monotonic() - started < 20
    assert_no_login_left(tmp_path)


def test_login_left_by_a_crashed_run_is_swept(tmp_path, fake_tool):
    old = tmp_path / "r-0001"
    osintgram.write_login(old, OWNER, PASSWORD)
    new = tmp_path / "r-0002"
    new.mkdir()
    osintgram.run(context(new)[0])
    assert_no_login_left(old)


def test_run_through_the_app_runner_leaves_no_login(qtbot, db, new_case, fake_tool, monkeypatch):
    from app.state import AppState

    keys = KeyStore(MemoryKeyring())
    keys.set_login(INSTAGRAM_LOGIN.name, OWNER, PASSWORD)
    monkeypatch.setattr(modules, "availability", lambda tool, db: Availability("Installed", True, "fake"))
    state = AppState(db, keys=keys)
    case = state.cases.create_case(new_case())
    target = state.cases.list_targets(case.id)[0]
    spec = state.module("osintgram")
    consent = state.consents.record(case.id, spec.name, spec.provider, target.value, scope_confirmed=True)
    with qtbot.waitSignal(state.runner.finished, timeout=30000) as done:
        state.runner.start(spec, case, target, consent)
    run = done.args[0].run
    assert run.status == "succeeded", run.error
    from pathlib import Path
    assert_no_login_left(Path(run.work_dir))
    assert "Instagram may block or ban" in spec.provider  # shown as "Sent to" in the consent dialog


def test_login_error_gives_a_clear_reason():
    line = json.dumps({"command": "login", "error": "InstagrapiBackendError: challenge_required"})
    with pytest.raises(ValueError, match="login with your account failed.*verification step"):
        osintgram.parse([line], target="example_user")
    with pytest.raises(ValueError, match="could not read @example_user"):
        osintgram.parse([json.dumps({"command": "info", "error": "TargetNotFoundError: not found"})],
                        target="example_user")


def test_no_login_stored_means_no_run(tmp_path, fake_tool):
    with pytest.raises(ValueError, match="Add your Instagram account"):
        osintgram.run(context(tmp_path, api_key=None)[0])
    assert not (tmp_path / "config").exists()


# ---------------------------------------------------------------- allowlist


FORBIDDEN = ("get_followers_email", "get_followings_email", "get_followers_phone", "get_followings_phone",
             "get_followers", "get_followings", "_contact_info", "compare_with")


def test_manifest_runs_only_target_focused_commands():
    tool = load_catalog().get("osintgram")
    osintgram.check_allowlist(tool)  # the shipped manifest passes
    code = " ".join(tool.launch.args)
    assert all(name not in code for name in FORBIDDEN)
    assert set(osintgram.ALLOWED) == {"info", "addrs", "captions", "hashtags", "mediatype", "tagged", "wtagged",
                                      "likes", "comments"}
    for method in osintgram.ALLOWED.values():
        assert method in code


@pytest.mark.parametrize("swap", [
    ('"get_user_info"', '"get_followers_email"'),
    ('"get_captions"', '"get_followings"'),
    ('("likes", "get_total_likes")', '("fwersnumber", "get_total_likes")'),
    ('"get_media_type"', '"compare_with"'),
])
def test_manifest_with_a_forbidden_command_is_refused(swap):
    tool = load_catalog().get("osintgram")
    code = tool.launch.args[1].replace(*swap)
    assert code != tool.launch.args[1]
    edited = tool.model_copy(update={"launch": tool.launch.model_copy(update={"args": ("-c", code, "{username}")})})
    with pytest.raises(ValueError, match="allowlist"):
        osintgram.check_allowlist(edited)


def test_osintgram_is_not_a_plain_tool_engine():
    """The plain runner would start it without writing and deleting the login."""
    assert all("osintgram" not in m.tools for m in discover())


# ---------------------------------------------------------------- status


def test_module_status_needs_login_then_install(db):
    spec = next(m for m in discover() if m.id == "osintgram")
    keys = KeyStore(MemoryKeyring())
    catalog = load_catalog()
    tool = catalog.get("osintgram")
    missing = tool.model_copy(update={"launch": tool.launch.model_copy(update={"venv": "envs/not_there_wp5"})})
    catalog.tools[catalog.tools.index(tool)] = missing
    assert module_status(spec, catalog, db, keys.has).label == "Needs key"
    keys.set_login(INSTAGRAM_LOGIN.name, OWNER, PASSWORD)
    status = module_status(spec, catalog, db, keys.has)
    assert status.label == "Not installed" and "Osintgram" in status.reason
    assert spec.labels == ("external", "passive", "api_key")
