"""Runner: argument-list execution, timeouts, output limits, cancellation, python jobs."""

from __future__ import annotations

import sys
import threading
import time

import pytest

from core.catalog import load_catalog
from core.findings import Finding
from core.manifest import ToolManifest
from core.paths import PROJECT_ROOT
from core.runner import CommandError, ProcessJob, PythonJob, build_command, minimal_environment


def run_job(qtbot, job, timeout_ms=20000):
    with qtbot.waitSignal(job.finished, timeout=timeout_ms) as blocker:
        job.start()
    return blocker.args[0]


def py(code: str) -> tuple[str, list[str]]:
    return sys.executable, ["-c", code]


def test_process_success_streams_lines_and_logs(qtbot, tmp_path):
    program, args = py("print('[+] GitHub: https://github.com/example_user'); print('\\x1b[32mdone\\x1b[0m')")
    log = tmp_path / "run.log"
    job = ProcessJob(program, args, tmp_path, timeout_s=20, max_output_kb=64, log_path=log)
    lines = []
    job.line.connect(lines.append)
    outcome = run_job(qtbot, job)
    assert outcome.status == "succeeded" and outcome.exit_code == 0
    assert lines == ["[+] GitHub: https://github.com/example_user", "done"]  # ANSI stripped
    text = log.read_text(encoding="utf-8")
    assert "# args:" in text and "done" in text and "# finished: succeeded" in text


def test_arguments_are_not_interpreted_by_a_shell(qtbot, tmp_path):
    marker = tmp_path / "pwned.txt"
    hostile = f"x & echo hacked > {marker}"
    program, args = py("import sys; print(sys.argv[1])")
    outcome = run_job(qtbot, ProcessJob(program, args + [hostile], tmp_path, timeout_s=20, max_output_kb=64))
    assert outcome.lines == [hostile]  # passed through as one literal argument
    assert not marker.exists()


def test_timeout_kills_the_process(qtbot, tmp_path):
    program, args = py("import time; print('start', flush=True); time.sleep(30)")
    started = time.monotonic()
    outcome = run_job(qtbot, ProcessJob(program, args, tmp_path, timeout_s=1, max_output_kb=64))
    assert outcome.status == "timed_out"
    assert "timeout" in outcome.error
    assert time.monotonic() - started < 15


def test_output_limit_stops_the_run(qtbot, tmp_path):
    program, args = py("import sys\nwhile True: sys.stdout.write('x' * 1000 + '\\n')")
    outcome = run_job(qtbot, ProcessJob(program, args, tmp_path, timeout_s=20, max_output_kb=16))
    assert outcome.status == "failed"
    assert "limit" in outcome.error


def test_stop_cancels(qtbot, tmp_path):
    program, args = py("import time; print('working', flush=True); time.sleep(30)")
    job = ProcessJob(program, args, tmp_path, timeout_s=30, max_output_kb=64)
    job.line.connect(lambda _line: job.stop())
    outcome = run_job(qtbot, job)
    assert outcome.status == "cancelled"


def test_nonzero_exit_and_missing_program(qtbot, tmp_path):
    program, args = py("import sys; print('boom'); sys.exit(3)")
    outcome = run_job(qtbot, ProcessJob(program, args, tmp_path, timeout_s=20, max_output_kb=64))
    assert (outcome.status, outcome.exit_code) == ("failed", 3)
    outcome = run_job(qtbot, ProcessJob(str(tmp_path / "nope.exe"), [], tmp_path, timeout_s=5, max_output_kb=64))
    assert outcome.status == "failed" and "Could not start" in outcome.error


def test_environment_has_no_secrets(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "example-secret")
    env = minimal_environment()
    assert "HIBP_API_KEY" not in env
    assert env["PYTHONIOENCODING"] == "utf-8"
    assert env["COLUMNS"] == "250"  # rich-based tools must not wrap URLs at 80 columns


def test_files_a_tool_writes_next_to_itself_move_into_its_run(qtbot, tmp_path):
    tool_dir, work_dir = tmp_path / "envs" / "tool" / "app", tmp_path / "case" / "runs" / "r-0001"
    (tool_dir / "data").mkdir(parents=True)
    (tool_dir / "data" / "sites.json").write_text("[]", encoding="utf-8")
    program, args = py("import os; os.makedirs('logs', exist_ok=True); "
                       "open('logs/tool.log', 'w').write('checked https://example.com/example_user')")
    job = ProcessJob(program, args, work_dir, timeout_s=20, max_output_kb=64, cwd=tool_dir,
                     log_path=tmp_path / "run.log")
    assert run_job(qtbot, job).status == "succeeded"
    assert not (tool_dir / "logs" / "tool.log").exists()
    assert "example_user" in (work_dir / "tool_files" / "logs" / "tool.log").read_text(encoding="utf-8")
    assert (tool_dir / "data" / "sites.json").exists()  # untouched tool data stays
    assert "tool_files/" in (tmp_path / "run.log").read_text(encoding="utf-8")


# ---------------------------------------------------------------- python jobs


def test_python_job_returns_findings(qtbot, tmp_path):
    def module(ctx):
        ctx.emit(f"checking {ctx.target}")
        return [Finding(module="Test", title="Example", source="test")]

    job = PythonJob(module, "domain", "example.com", tmp_path, timeout_s=10, max_output_kb=64,
                    log_path=tmp_path / "run.log")
    outcome = run_job(qtbot, job)
    assert outcome.status == "succeeded"
    assert outcome.lines == ["checking example.com"]
    assert [f.title for f in outcome.findings] == ["Example"]


def test_python_job_errors_and_timeouts(qtbot, tmp_path):
    def broken(ctx):
        raise RuntimeError("provider down")

    outcome = run_job(qtbot, PythonJob(broken, "domain", "example.com", tmp_path, timeout_s=10, max_output_kb=64))
    assert outcome.status == "failed" and "provider down" in outcome.error

    def slow(ctx):
        for _ in range(100):
            time.sleep(0.05)
            ctx.check()
        return []

    outcome = run_job(qtbot, PythonJob(slow, "domain", "example.com", tmp_path, timeout_s=1, max_output_kb=64))
    assert outcome.status == "timed_out"


# ---------------------------------------------------------------- building commands


@pytest.fixture
def sherlock() -> ToolManifest:
    return load_catalog().get("sherlock")


def fake_install(tool: ToolManifest, root):
    program = root / f"{tool.launch.venv}/Scripts/python.exe" if tool.launch.venv else root / tool.launch.executable
    program.parent.mkdir(parents=True, exist_ok=True)
    program.write_bytes(b"fake")
    return program


def test_build_command_substitutes_validated_target(sherlock, tmp_path):
    program = fake_install(sherlock, tmp_path)
    exe, args = build_command(sherlock, "username", "@example_user", tmp_path / "run", root=tmp_path)
    assert exe == str(program)
    assert args[:3] == ["-m", "sherlock_project", "example_user"]
    assert "--local" in args


@pytest.mark.parametrize(
    "target_type, value, message",
    [
        ("email", "owner@example.com", "does not accept"),
        ("username", "-rf", "can't start"),
        ("username", "a b", "Usernames use"),
    ],
)
def test_build_command_rejects_bad_targets(sherlock, tmp_path, target_type, value, message):
    fake_install(sherlock, tmp_path)
    with pytest.raises(Exception) as info:
        build_command(sherlock, target_type, value, tmp_path, root=tmp_path)
    assert message in str(info.value)


def test_build_command_requires_install_and_integration(sherlock, tmp_path):
    with pytest.raises(CommandError, match="not installed"):
        build_command(sherlock, "username", "example_user", tmp_path, root=tmp_path)
    amass = load_catalog().get("amass")  # v5 needs an engine service: deliberately not integrated
    with pytest.raises(CommandError, match="not integrated"):
        build_command(amass, "domain", "example.com", tmp_path, root=tmp_path)


def test_pinned_hash_is_enforced(tmp_path):
    exiftool = load_catalog().get("exiftool")
    sample = tmp_path / "profile_01.png"
    sample.write_bytes(b"fake image")
    fake_install(exiftool, tmp_path)  # wrong bytes -> wrong hash
    with pytest.raises(CommandError, match="integrity"):
        build_command(exiftool, "file", str(sample), tmp_path, root=tmp_path)


def test_exiftool_whole_folder_is_pinned(tmp_path):
    exiftool = load_catalog().get("exiftool")
    assert exiftool.launch.tree == "bin/exiftool_files" and exiftool.launch.tree_sha256
    sample = tmp_path / "profile_01.png"
    sample.write_bytes(b"fake image")
    real = PROJECT_ROOT / exiftool.launch.executable
    if not real.is_file():
        pytest.skip("ExifTool not installed")
    (tmp_path / "bin" / "exiftool_files").mkdir(parents=True)
    (tmp_path / "bin" / "exiftool.exe").write_bytes(real.read_bytes())  # right launcher, empty folder
    with pytest.raises(CommandError, match="exiftool_files"):
        build_command(exiftool, "file", str(sample), tmp_path, root=tmp_path)


def test_late_module_result_after_timeout_is_dropped_quietly(tmp_path):
    import shiboken6

    from core.runner import ModuleContext, _Bridge, _Worker

    bridge = _Bridge()
    ctx = ModuleContext("domain", "example.com", tmp_path, lambda text: None, threading.Event())
    worker = _Worker(lambda c: [], ctx, bridge)
    shiboken6.delete(bridge)  # the timed-out job and its bridge are gone when the module returns
    worker.run()  # must not raise "Signal source has been deleted"


def test_a_failing_tool_shows_its_own_error_line(qtbot, tmp_path):
    program, args = py("import sys; print('checking example.com'); print('ERROR: no route to host'); "
                       "print('bye'); sys.exit(2)")
    outcome = run_job(qtbot, ProcessJob(program, args, tmp_path, timeout_s=20, max_output_kb=64))
    assert outcome.status == "failed" and outcome.error == "ERROR: no route to host"


def test_stderr_can_go_to_a_file_in_the_run_folder(qtbot, tmp_path):
    program, args = py("import sys; print('result'); print('noisy traceback', file=sys.stderr)")
    job = ProcessJob(program, args, tmp_path, timeout_s=20, max_output_kb=64, stderr_file=True)
    outcome = run_job(qtbot, job)
    assert outcome.lines == ["result"]
    assert "noisy traceback" in (tmp_path / "stderr.log").read_text(encoding="utf-8")


def test_a_tool_that_asks_for_input_gets_eof_instead_of_hanging(qtbot, tmp_path):
    program, args = py("import sys\ntry:\n    input('2FA code: ')\nexcept EOFError:\n    print('no input'); sys.exit(4)")
    outcome = run_job(qtbot, ProcessJob(program, args, tmp_path, timeout_s=20, max_output_kb=64), timeout_ms=10000)
    assert outcome.exit_code == 4 and outcome.duration_s < 10
