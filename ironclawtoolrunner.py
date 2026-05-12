from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final

from ironclawshellguard import GuardedCommandResult, run_guarded_command

DEFAULT_TIMEOUT_SECONDS: Final[float] = 20.0
DEFAULT_AUDIT_FILE: Final[Path] = Path(__file__).resolve().with_name(".ironclawtoolrunner-audit.json")


class IronClawToolRunnerError(RuntimeError):
    """Base tool runner error."""


class IronClawToolRegistrationError(IronClawToolRunnerError):
    """Raised when a tool definition is invalid."""


class IronClawToolExecutionError(IronClawToolRunnerError):
    """Raised when tool execution fails."""


@dataclass(frozen=True, slots=True)
class IronClawToolSpec:
    name: str
    command: tuple[str, ...]
    description: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise IronClawToolRegistrationError("Tool name cannot be empty.")
        if not self.command:
            raise IronClawToolRegistrationError(f"Tool {self.name!r} must define a command.")
        if self.timeout_seconds <= 0:
            raise IronClawToolRegistrationError(f"Tool {self.name!r} timeout must be positive.")


@dataclass(frozen=True, slots=True)
class IronClawToolRunResult:
    tool_name: str
    ok: bool
    duration_ms: int
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IronClawToolRunner:
    """
    Secure registry-backed tool executor for IronClaw.

    Design goals:
    - explicit registration only
    - no ad-hoc arbitrary shell execution
    - execution routed through ironclawshellguard
    - auditable structured result output
    """

    def __init__(
        self,
        *,
        audit_file: Path | None = None,
        before_run: Callable[[IronClawToolSpec], None] | None = None,
        after_run: Callable[[IronClawToolRunResult], None] | None = None,
    ) -> None:
        self._tools: dict[str, IronClawToolSpec] = {}
        self._audit_file = (audit_file or DEFAULT_AUDIT_FILE).resolve()
        self._before_run = before_run
        self._after_run = after_run

    @property
    def audit_file(self) -> Path:
        return self._audit_file

    def register(self, spec: IronClawToolSpec) -> None:
        key = self._normalize_name(spec.name)
        if key in self._tools:
            raise IronClawToolRegistrationError(f"Tool already registered: {spec.name}")
        self._tools[key] = spec

    def register_many(self, specs: list[IronClawToolSpec] | tuple[IronClawToolSpec, ...]) -> None:
        for spec in specs:
            self.register(spec)

    def is_registered(self, tool_name: str) -> bool:
        return self._normalize_name(tool_name) in self._tools

    def get_spec(self, tool_name: str) -> IronClawToolSpec:
        key = self._normalize_name(tool_name)
        try:
            return self._tools[key]
        except KeyError as exc:
            raise IronClawToolExecutionError(f"Unknown tool: {tool_name}") from exc

    def list_tools(self) -> list[str]:
        return sorted(spec.name for spec in self._tools.values())

    def run(self, tool_name: str) -> IronClawToolRunResult:
        spec = self.get_spec(tool_name)

        if self._before_run is not None:
            self._before_run(spec)

        started = time.perf_counter()
        try:
            guarded_result = run_guarded_command(
                spec.command,
                timeout_seconds=spec.timeout_seconds,
                cwd=spec.cwd,
                env=spec.env,
                check=False,
            )
        except Exception as exc:
            raise IronClawToolExecutionError(f"Tool {spec.name!r} failed to execute: {exc}") from exc

        duration_ms = round((time.perf_counter() - started) * 1000)
        result = self._build_result(spec, guarded_result, duration_ms)
        self._append_audit(spec, result)

        if self._after_run is not None:
            self._after_run(result)

        if not result.ok:
            raise IronClawToolExecutionError(
                f"Tool {spec.name!r} exited with code {result.returncode}"
            )

        return result

    def run_all(self, *, fail_fast: bool = True) -> list[IronClawToolRunResult]:
        results: list[IronClawToolRunResult] = []

        for tool_name in self.list_tools():
            try:
                results.append(self.run(tool_name))
            except IronClawToolExecutionError:
                if fail_fast:
                    raise
                spec = self.get_spec(tool_name)
                fallback = IronClawToolRunResult(
                    tool_name=spec.name,
                    ok=False,
                    duration_ms=0,
                    command=spec.command,
                    returncode=None,
                    stdout="",
                    stderr="tool execution failed before result capture",
                )
                results.append(fallback)

        return results

    def run_named(self, tool_names: list[str] | tuple[str, ...], *, fail_fast: bool = True) -> list[IronClawToolRunResult]:
        results: list[IronClawToolRunResult] = []

        for tool_name in tool_names:
            try:
                results.append(self.run(tool_name))
            except IronClawToolExecutionError:
                if fail_fast:
                    raise
                spec = self.get_spec(tool_name)
                fallback = IronClawToolRunResult(
                    tool_name=spec.name,
                    ok=False,
                    duration_ms=0,
                    command=spec.command,
                    returncode=None,
                    stdout="",
                    stderr="tool execution failed before result capture",
                )
                results.append(fallback)

        return results

    def summary(self) -> dict[str, Any]:
        return {
            "registered_tools": self.list_tools(),
            "count": len(self._tools),
            "audit_file": str(self._audit_file),
        }

    def _build_result(
        self,
        spec: IronClawToolSpec,
        guarded_result: GuardedCommandResult,
        duration_ms: int,
    ) -> IronClawToolRunResult:
        return IronClawToolRunResult(
            tool_name=spec.name,
            ok=guarded_result.ok,
            duration_ms=duration_ms,
            command=guarded_result.command,
            returncode=guarded_result.returncode,
            stdout=guarded_result.stdout,
            stderr=guarded_result.stderr,
        )

    def _append_audit(self, spec: IronClawToolSpec, result: IronClawToolRunResult) -> None:
        self._audit_file.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": spec.name,
            "description": spec.description,
            "result": result.to_dict(),
        }
        with self._audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    @staticmethod
    def _normalize_name(tool_name: str) -> str:
        normalized = tool_name.strip().lower()
        if not normalized:
            raise IronClawToolRegistrationError("Tool name cannot be empty.")
        return normalized


def build_default_tool_runner() -> IronClawToolRunner:
    runner = IronClawToolRunner()
    runner.register_many(
        [
            IronClawToolSpec(
                name="python-version",
                command=("python", "--version"),
                description="Verify Python runtime availability.",
                timeout_seconds=5.0,
            ),
            IronClawToolSpec(
                name="pytest-quick",
                command=("pytest", "-q"),
                description="Run the project test suite in quiet mode.",
                timeout_seconds=60.0,
            ),
            IronClawToolSpec(
                name="ruff-check",
                command=("ruff", "check", "."),
                description="Run Ruff static analysis across the repository.",
                timeout_seconds=30.0,
            ),
        ]
    )
    return runner