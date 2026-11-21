"""Safe execution (docs/PROJECT_RULES.md rules 1-2, plan section 8.3).

- Subprocess tools run through QProcess with an argument list: never a shell.
  The program and arguments come only from the tool's manifest; the target is
  re-validated and substituted as one whole argument.
- Every run has a timeout, an output-size limit, its own work folder and a log.
- Python modules run on a worker thread so the UI never blocks.
"""

from __future__ import annotations

import codecs
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, QRunnable, QThreadPool, QTimer, Signal

from core.manifest import LaunchKind, ToolManifest
from core.paths import PROJECT_ROOT
from core.validation import TargetType, validate_target

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


class CommandError(Exception):
    """The tool can't be run as requested. The message is shown to the user."""


@dataclass
class RunOutcome:
    status: str                      # succeeded / failed / timed_out / cancelled
    exit_code: int | None = None
    output_bytes: int = 0
    lines: list[str] = field(default_factory=list)
    error: str | None = None
    duration_s: float = 0.0
    findings: list | None = None     # python modules return findings directly


def clean_line(text: str) -> str:
    return _ANSI.sub("", text).replace("\r", "").rstrip()


# ---------------------------------------------------------------- building commands

_hash_cache: dict[tuple[str, int, int], str] = {}


def sha256_file(path: Path) -> str:
    stat = path.stat()
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    if key not in _hash_cache:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        _hash_cache[key] = digest.hexdigest()
    return _hash_cache[key]


def tree_sha256(folder: Path) -> str:
    """One SHA-256 over every file in the folder (sorted relative path + file hash), so any change shows."""
    digest = hashlib.sha256()
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        digest.update(f"{path.relative_to(folder).as_posix()}\0{sha256_file(path)}\n".encode())
    return digest.hexdigest()


def tool_program(tool: ToolManifest, root: Path = PROJECT_ROOT) -> Path:
    launch = tool.launch
    if launch.kind is not LaunchKind.SUBPROCESS:
        raise CommandError(f"{tool.name} is not a local program.")
    program = root / (f"{launch.venv}/Scripts/python.exe" if launch.venv else launch.executable)
    if not program.is_file():
        raise CommandError(f"{tool.name} is not installed (expected {program.relative_to(root).as_posix()}).")
    if launch.sha256 and sha256_file(program) != launch.sha256:
        raise CommandError(
            f"{tool.name} failed its integrity check: {program.name} does not match the pinned SHA-256. "
            "Reinstall the pinned version."
        )
    if launch.tree and (not (root / launch.tree).is_dir() or tree_sha256(root / launch.tree) != launch.tree_sha256):
        raise CommandError(
            f"{tool.name} failed its integrity check: {launch.tree} does not match the pinned SHA-256. "
            "Reinstall the pinned version."
        )
    return program


def tool_cwd(tool: ToolManifest, work_dir: Path, root: Path = PROJECT_ROOT) -> Path:
    """Where the process starts: its run folder, or the script's folder for tools that need it."""
    if tool.launch.cwd == "script":
        return (root / tool.launch.script).parent
    return work_dir


def build_command(tool: ToolManifest, target_type: TargetType | str, target_value: str, work_dir: Path,
                  root: Path = PROJECT_ROOT) -> tuple[str, list[str]]:
    """Program + argument list from the manifest. No free-form input reaches the command."""
    kind = TargetType(target_type)
    if kind not in tool.target_types:
        raise CommandError(f"{tool.name} does not accept a {kind.label.lower()}.")
    if not tool.launch.args:
        raise CommandError(f"{tool.name} is in the catalog but not integrated yet.")
    value = validate_target(kind, target_value)
    program = tool_program(tool, root)
    substitutions = {
        kind.value: value,
        "out_file": str(work_dir / "output.json"),
        "work_dir": str(work_dir),
    }
    args = []
    if tool.launch.script:
        script = root / tool.launch.script
        if not script.is_file():
            raise CommandError(f"{tool.name} is not installed (expected {tool.launch.script}).")
        args.append(str(script))
    for arg in tool.launch.args:
        if arg.startswith("{") and arg.endswith("}"):
            name = arg[1:-1]
            if name not in substitutions:
                raise CommandError(f"{tool.name} needs a {name} target for this run.")
            args.append(substitutions[name])
        else:
            args.append(arg)
    return str(program), args


def minimal_environment() -> dict[str, str]:
    """Only what tools need to start: no API keys or other secrets from the parent environment."""
    keep = ("SYSTEMDRIVE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
            "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    system_root = env.get("SYSTEMROOT", r"C:\Windows")
    env.update(
        PATH=rf"{system_root}\System32",
        PYTHONIOENCODING="utf-8",
        PYTHONUTF8="1",
        PYTHONUNBUFFERED="1",
        NO_COLOR="1",
        COLUMNS="250",  # rich-based tools (Blackbird) wrap at 80 columns when piped and cut URLs
    )
    return env


def _last_error(lines: list[str]) -> str:
    """The tool's own reason for failing: its last 'error' line, else its last line (cut to 300 chars)."""
    for line in reversed(lines):
        if line.strip().lower().startswith(("error", "[error]", "[-] error")):
            return line.strip()[:300]
    return lines[-1].strip()[:300] if lines else ""


def _snapshot(folder: Path) -> dict[Path, tuple[int, int]]:
    """Files under a tool's own folder (bytecode caches aside), to spot what a run writes there."""
    snapshot = {}
    for path in folder.rglob("*"):
        if "__pycache__" not in path.parts and path.is_file():
            stat = path.stat()
            snapshot[path] = (stat.st_size, stat.st_mtime_ns)
    return snapshot


def collect_strays(folder: Path, before: dict[Path, tuple[int, int]], dest: Path) -> list[str]:
    """Move files the run created or changed under `folder` into `dest`, so case data stays with the case."""
    moved = []
    for path, stamp in _snapshot(folder).items():
        if before.get(path) != stamp:
            relative = path.relative_to(folder)
            target = dest / relative
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(path, target)
            except OSError:
                continue  # shortcut: a file still locked stays behind, add a retry if a tool ever holds one
            moved.append(relative.as_posix())
    return moved


# ---------------------------------------------------------------- jobs


class Job(QObject):
    line = Signal(str)
    finished = Signal(object)  # RunOutcome

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError


class _RunLog:
    def __init__(self, path: Path | None):
        self._handle = path.open("w", encoding="utf-8", newline="\n") if path else None

    def write(self, text: str) -> None:
        if self._handle:
            self._handle.write(text + "\n")
            self._handle.flush()

    def close(self) -> None:
        if self._handle:
            self._handle.close()
            self._handle = None


class ProcessJob(Job):
    """One tool run in a separate process, with timeout and output limit."""

    def __init__(self, program: str, args: list[str], work_dir: Path, *, timeout_s: int, max_output_kb: int,
                 log_path: Path | None = None, env: dict[str, str] | None = None, cwd: Path | None = None,
                 stderr_file: bool = False):
        super().__init__()
        self.program, self.args, self.work_dir = program, list(args), Path(work_dir)
        self.cwd = Path(cwd) if cwd else self.work_dir
        # A tool started in its own folder may write there (Blackbird's logs/): those files move to the run.
        self._before = None if self.cwd == self.work_dir else {}
        self.timeout_ms = timeout_s * 1000
        self.max_bytes = max_output_kb * 1024
        self._env = env if env is not None else minimal_environment()
        self._log = _RunLog(log_path)
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._pending = ""
        self._outcome = RunOutcome(status="failed")
        self._forced: str | None = None
        self._done = False
        self._started = 0.0
        self._process = QProcess(self)
        self._stderr_file = stderr_file
        self._process.setStandardInputFile(QProcess.nullDevice())  # a tool that prompts gets EOF, never hangs to the timeout
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels if stderr_file
                                            else QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._read)
        self._process.finished.connect(self._on_finished)
        self._process.errorOccurred.connect(self._on_error)
        self._timer = QTimer(self, singleShot=True)
        self._timer.timeout.connect(lambda: self._abort("timed_out", f"Stopped after the {self.timeout_ms // 1000} s timeout."))

    def start(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        if self._stderr_file:
            self._process.setStandardErrorFile(str(self.work_dir / "stderr.log"))
        env = QProcessEnvironment()
        for key, value in self._env.items():
            env.insert(key, value)
        self._process.setProcessEnvironment(env)
        self._process.setWorkingDirectory(str(self.cwd))
        self._log.write(f"# program: {self.program}")
        self._log.write(f"# args: {self.args!r}")
        self._log.write(f"# timeout: {self.timeout_ms // 1000} s, max output: {self.max_bytes // 1024} KB")
        self._log.write(f"# started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        if self._before is not None:
            self._before = _snapshot(self.cwd)
        self._started = time.monotonic()
        self._timer.start(self.timeout_ms)
        self._process.start(self.program, self.args)  # argument list: no shell is involved

    def stop(self) -> None:
        self._abort("cancelled", "Stopped by you.")

    def _abort(self, status: str, message: str) -> None:
        if self._done or self._forced:
            return
        self._forced = status
        self._outcome.error = message
        _kill_tree(self._process)

    def _read(self) -> None:
        data = bytes(self._process.readAllStandardOutput())
        self._outcome.output_bytes += len(data)
        if self._outcome.output_bytes > self.max_bytes:
            self._abort("failed", f"Output exceeded the {self.max_bytes // 1024} KB limit; the run was stopped.")
            return
        self._pending += self._decoder.decode(data)
        *complete, self._pending = self._pending.split("\n")
        for raw in complete:
            self._emit(raw)

    def _emit(self, raw: str) -> None:
        text = clean_line(raw)
        if not text.strip():
            return
        self._outcome.lines.append(text)
        self._log.write(text)
        self.line.emit(text)

    def _on_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.FailedToStart:
            self._outcome.error = f"Could not start {Path(self.program).name}: {self._process.errorString()}"
            self._finish(None)

    def _on_finished(self, exit_code: int, _status) -> None:
        self._read()
        tail = self._pending + self._decoder.decode(b"", final=True)
        if tail.strip():
            self._emit(tail)
        self._pending = ""
        self._finish(exit_code)

    def _finish(self, exit_code: int | None) -> None:
        if self._done:
            return
        self._done = True
        self._timer.stop()
        outcome = self._outcome
        outcome.exit_code = exit_code
        outcome.duration_s = round(time.monotonic() - self._started, 1)
        if self._forced:
            outcome.status = self._forced
        elif exit_code == 0:
            outcome.status = "succeeded"
        else:
            outcome.status = "failed"
            outcome.error = outcome.error or _last_error(outcome.lines) or                 f"{Path(self.program).name} exited with code {exit_code}."
        if self._before is not None:
            moved = collect_strays(self.cwd, self._before, self.work_dir / "tool_files")
            if moved:
                self._log.write(f"# moved into tool_files/ (written next to the tool): {', '.join(moved)}")
        self._log.write(f"# finished: {outcome.status}, exit code {exit_code}, {outcome.duration_s} s, "
                        f"{outcome.output_bytes} bytes" + (f" - {outcome.error}" if outcome.error else ""))
        self._log.close()
        self.finished.emit(outcome)


def _kill_tree(process: QProcess) -> None:
    """Kill the process and its children (a venv python.exe is a launcher with a child)."""
    pid = process.processId()
    if pid and sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    process.kill()


# ---------------------------------------------------------------- python modules


class ModuleContext:
    """What a python module sees: the validated target, its work folder and a way to report lines."""

    def __init__(self, target_type: TargetType, target_value: str, work_dir: Path,
                 emit: Callable[[str], None], cancel: threading.Event, services: dict | None = None):
        self.target_type = target_type
        self.target = target_value
        self.work_dir = work_dir
        self._emit = emit
        self._cancel = cancel
        self.services = services or {}
        self._http = None

    def http(self):
        """Rate-limited, cached HTTP client for this run (see core.net)."""
        if self._http is None:
            self._http = self.services["http_factory"](self.check)
        return self._http

    @property
    def api_key(self) -> str | None:
        return self.services.get("api_key")

    def setting(self, key: str, default=None):
        return self.services.get("settings", {}).get(key, default)

    def close(self) -> None:
        if self._http is not None:
            self._http.close()

    def emit(self, text: str) -> None:
        if self._cancel.is_set():
            raise JobCancelled()
        self._emit(clean_line(text))

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check(self) -> None:
        if self._cancel.is_set():
            raise JobCancelled()


class JobCancelled(Exception):
    pass


class _Bridge(QObject):
    line = Signal(str)
    done = Signal(object, object)  # findings | None, error | None


class _Worker(QRunnable):
    def __init__(self, fn, ctx: ModuleContext, bridge: _Bridge):
        super().__init__()
        self.fn, self.ctx, self.bridge = fn, ctx, bridge

    def run(self) -> None:
        try:
            result = (list(self.fn(self.ctx) or []), None)
        except JobCancelled:
            result = (None, None)
        except Exception as exc:  # reported to the user, never crashes the app
            message = str(exc) if type(exc).__name__ in ("NetError", "ValueError") else f"{type(exc).__name__}: {exc}"
            result = (None, message)
        finally:
            self.ctx.close()
        try:
            self.bridge.done.emit(*result)
        except RuntimeError:  # a late result after a timeout or stop: the job is already gone
            pass


class PythonJob(Job):
    """A built-in module function on a worker thread, with timeout and output limit."""

    def __init__(self, fn: Callable[[ModuleContext], list], target_type: TargetType, target_value: str,
                 work_dir: Path, *, timeout_s: int, max_output_kb: int, log_path: Path | None = None,
                 services: dict | None = None, pool: QThreadPool | None = None):
        super().__init__()
        self.work_dir = Path(work_dir)
        self.timeout_ms = timeout_s * 1000
        self.max_bytes = max_output_kb * 1024
        self._cancel = threading.Event()
        self._bridge = _Bridge()
        self._bridge.line.connect(self._on_line)
        self._bridge.done.connect(self._on_done)
        self._ctx = ModuleContext(TargetType(target_type), target_value, self.work_dir,
                                  self._bridge.line.emit, self._cancel, services)
        self._fn = fn
        self._pool = pool or QThreadPool.globalInstance()
        self._log = _RunLog(log_path)
        self._outcome = RunOutcome(status="failed")
        self._forced: str | None = None
        self._done = False
        self._started = 0.0
        self._timer = QTimer(self, singleShot=True)
        self._timer.timeout.connect(lambda: self._abort("timed_out", f"Stopped after the {self.timeout_ms // 1000} s timeout."))

    def start(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._log.write(f"# module: {getattr(self._fn, '__module__', '?')}.{getattr(self._fn, '__name__', '?')}")
        self._log.write(f"# timeout: {self.timeout_ms // 1000} s, max output: {self.max_bytes // 1024} KB")
        self._log.write(f"# started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self._started = time.monotonic()
        self._timer.start(self.timeout_ms)
        self._pool.start(_Worker(self._fn, self._ctx, self._bridge))

    def stop(self) -> None:
        self._abort("cancelled", "Stopped by you.")

    def _abort(self, status: str, message: str) -> None:
        if self._done:
            return
        self._cancel.set()
        self._forced = status
        self._outcome.error = message
        self._finish(None)  # don't wait for the worker; its late result is ignored

    def _on_line(self, text: str) -> None:
        if self._done or not text.strip():
            return
        self._outcome.output_bytes += len(text.encode("utf-8")) + 1
        if self._outcome.output_bytes > self.max_bytes:
            self._abort("failed", f"Output exceeded the {self.max_bytes // 1024} KB limit; the run was stopped.")
            return
        self._outcome.lines.append(text)
        self._log.write(text)
        self.line.emit(text)

    def _on_done(self, findings, error) -> None:
        if self._done:
            return
        if error:
            self._outcome.error = error
            self._finish(None, failed=True)
        else:
            self._outcome.findings = findings
            self._finish(0)

    def _finish(self, exit_code: int | None, failed: bool = False) -> None:
        if self._done:
            return
        self._done = True
        self._timer.stop()
        outcome = self._outcome
        outcome.exit_code = exit_code
        outcome.duration_s = round(time.monotonic() - self._started, 1)
        outcome.status = self._forced or ("failed" if failed else "succeeded")
        self._log.write(f"# finished: {outcome.status}, {outcome.duration_s} s"
                        + (f" - {outcome.error}" if outcome.error else ""))
        self._log.close()
        self.finished.emit(outcome)
