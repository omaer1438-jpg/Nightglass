"""Run controller: gates -> run record -> job -> parse -> findings (one run at a time)."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from core.cases import Case, Target
from core.findings import FindingStore
from core.manifest import ToolManifest
from core.modules import Engine, ModuleSpec, ParseResult, check_gates, module_status, parser_for, pick_engine
from core.runner import (
    CommandError,
    Job,
    ProcessJob,
    PythonJob,
    RunOutcome,
    build_command,
    minimal_environment,
    tool_cwd,
)
from core.runs import ConsentRecord, RunRecord, RunStore


@dataclass
class ActiveRun:
    spec: ModuleSpec
    case: Case
    target: Target
    run: RunRecord
    tool: ToolManifest | None
    consent: ConsentRecord | None
    engine: Engine
    timeout_s: int
    max_output_kb: int
    lines: list[tuple[str, str]] = field(default_factory=list)  # (text, console tag)
    outcome: RunOutcome | None = None
    result: ParseResult | None = None
    finding_ids: list[int] = field(default_factory=list)

    @property
    def running(self) -> bool:
        return self.outcome is None

    @property
    def source(self) -> str:
        return self.tool.name if self.tool else "built-in"


class RunController(QObject):
    started = Signal(object)        # ActiveRun
    line = Signal(str, str)         # text, tag
    finished = Signal(object)       # ActiveRun

    def __init__(self, state):
        super().__init__()
        self.state = state
        self.current: ActiveRun | None = None
        self._job: Job | None = None

    @property
    def busy(self) -> bool:
        return self.current is not None and self.current.running

    def has_active_run(self, case_id: int) -> bool:
        """True while a run of this case is still going (closing or deleting it must wait)."""
        return self.busy and self.current.case.id == case_id

    def engine(self, spec: ModuleSpec, engine_id: str | None = None) -> Engine | None:
        return pick_engine(spec, self.state.catalog, self.state.db, self.state.keys.has, engine_id)

    def problems(self, spec: ModuleSpec, case: Case, target: Target, engine_id: str | None = None) -> list[str]:
        if self.busy:
            return ["Another module is still running. Stop it or wait for it to finish."]
        engine = self.engine(spec, engine_id)
        if engine is None:
            status = module_status(spec, self.state.catalog, self.state.db, self.state.keys.has)
            reason = status.reason if not status.ready else f"{engine_id} is not available for {spec.name}."
            return [reason] + check_gates(spec, case, target.type, target.value, self.state.db)
        return check_gates(spec, case, target.type, target.value, self.state.db, engine)

    def start(self, spec: ModuleSpec, case: Case, target: Target, consent: ConsentRecord | None,
              engine_id: str | None = None) -> ActiveRun:
        problems = self.problems(spec, case, target, engine_id)
        if problems:
            raise CommandError(" ".join(problems))
        engine = self.engine(spec, engine_id)
        if engine.is_external and consent is None:
            raise CommandError("External lookups need a logged consent first.")
        if engine.is_active and (consent is None or not consent.active or consent.remembered):
            raise CommandError("Active lookups need a fresh, scope-confirmed consent.")
        tool = engine.tool
        runs: RunStore = self.state.run_store
        run = runs.create(case.id, spec.name, target_id=target.id, tool_id=tool.id if tool else None,
                          external=engine.is_external, active=engine.is_active)
        if consent is not None:
            self.state.consents.attach_run(consent.id, run.id)
        work_dir, log_path = Path(run.work_dir), Path(run.log_path)
        cap = self.state.db.get_setting("timeout_cap_s", 0) or 10**6  # Settings "Timeout limit"; 0 = no cap
        if tool is not None:
            timeout_s, max_kb = min(tool.launch.timeout_s, cap), tool.launch.max_output_kb
            try:
                program, args = build_command(tool, target.type, target.value, work_dir)
            except CommandError as exc:
                runs.finish(run.id, "failed", error=str(exc))
                raise
            env = {**minimal_environment(), "USERPROFILE": str(work_dir)} if tool.launch.own_home else None
            job: Job = ProcessJob(program, args, work_dir, timeout_s=timeout_s, max_output_kb=max_kb,
                                  log_path=log_path, env=env, cwd=tool_cwd(tool, work_dir),
                                  stderr_file=tool.launch.stderr == "file")
        else:
            timeout_s = min(spec.timeout_s or 180, cap)
            max_kb = spec.max_output_kb
            job = PythonJob(spec.run, target.type, target.value, work_dir, timeout_s=timeout_s,
                            max_output_kb=max_kb, log_path=log_path, services=self.state.services(spec))
        self.current = ActiveRun(spec, case, target, runs.get(run.id), tool, consent, engine, timeout_s, max_kb)
        self._job = job
        job.line.connect(self._on_line)
        job.finished.connect(self._on_finished)
        runs.mark_running(run.id)
        self.started.emit(self.current)
        job.start()
        return self.current

    def stop(self) -> None:
        if self._job is not None and self.busy:
            self._job.stop()

    def _on_line(self, text: str) -> None:
        current = self.current
        tag = current.spec.console_tag(text) if current.spec.console_tag else ""
        current.lines.append((text, tag))
        self.line.emit(text, tag)

    def _on_finished(self, outcome: RunOutcome) -> None:
        current = self.current
        current.outcome = outcome
        status, error = outcome.status, outcome.error
        # Partial output (timeout, stop, non-zero exit) is still parsed: those leads are real.
        if status == "succeeded" or (outcome.lines and current.tool is not None):
            try:
                if current.tool is not None:
                    parse = parser_for(current.tool)
                    current.result = parse(outcome.lines, Path(current.run.work_dir), current.target.value)
                else:
                    current.result = ParseResult(outcome.findings or [], {})
            except Exception as exc:  # bad tool output is a failed run, not a crash
                problem = f"Could not read the tool's output: {exc}"
                if status == "succeeded":
                    status, error = "failed", problem
                else:  # the timeout / stop / exit reason is the real one: keep it
                    _append_log(current.run.log_path, problem)
        try:
            if current.result and current.result.findings:
                store: FindingStore = self.state.findings
                current.finding_ids = store.add(current.case.id, current.result.findings, current.run.id,
                                                current.target.id)
        except Exception as exc:  # e.g. the case was deleted or closed mid-run: the run fails, the UI moves on
            current.finding_ids = []
            status, error = "failed", f"Could not save the findings: {exc}"
            _append_log(current.run.log_path, error)
        try:
            current.run = self.state.run_store.finish(
                current.run.id, status, exit_code=outcome.exit_code, output_bytes=outcome.output_bytes,
                summary=summarize(current.result), error=error,
            )
        except Exception as exc:
            _append_log(current.run.log_path, f"Could not record the run's end: {exc}")
            current.run = replace(current.run, status=status, error=error)
        self._job = None
        self.finished.emit(current)
        try:
            self.state.case_updated(self.state.cases.get_case(current.case.id))
        except Exception:  # the case is gone; the screens already refreshed when it was deleted
            pass


def _append_log(log_path: str | None, text: str) -> None:
    if log_path:
        try:
            with open(log_path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(f"# {text}\n")
        except OSError:
            pass


def summarize(result: ParseResult | None) -> str:
    if result is None:
        return ""
    counts = dict(result.counts)
    if not counts:
        counts = {"findings": len(result.findings)}
    return ", ".join(f"{value} {key.replace('_', ' ')}" for key, value in counts.items())
