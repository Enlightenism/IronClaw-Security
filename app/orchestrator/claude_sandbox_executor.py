from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, runtime_checkable

from app.orchestrator.secure_runtime_pipeline import (
    ActionExecutionContext,
    GuardedActionRequest,
    GuardedActionResult,
)

ExecutionMode = Literal["dryrun", "sandboxed", "direct"]


@runtime_checkable
class SandboxRunner(Protocol):
    """Minimal protocol for a sandbox runner.

    A concrete implementation could:
      - talk to a firecracker/microVM pool,
      - use containerized sandboxes,
      - or isolate via a dedicated constrained worker process.
    """

    def run(
        self,
        action_type: str,
        target: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
        read_only_fs: bool = True,
        network_enabled: bool = False,
    ) -> dict[str, Any]: ...


@dataclass
class SandboxExecutorConfig:
    """Configuration for the Claude-focused sandbox executor."""

    name: str = "claude-sandbox-executor"
    mode: ExecutionMode = "dryrun"
    timeout_seconds: float = 8.0
    require_sandbox_for_shell: bool = True
    require_sandbox_for_network: bool = True


class NoopSandboxRunner:
    """Default in-process sandbox runner placeholder.

    This does NOT provide real isolation. It exists purely to keep the
    orchestration path wired while a real sandbox backend is integrated.
    """

    def run(
        self,
        action_type: str,
        target: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
        read_only_fs: bool = True,
        network_enabled: bool = False,
    ) -> dict[str, Any]:
        # TODO: replace with a real sandbox driver.
        return {
            "status": "simulated",
            "executor": "noop",
            "action_type": action_type,
            "target": target,
            "timeout_seconds": timeout_seconds,
            "read_only_fs": read_only_fs,
            "network_enabled": network_enabled,
        }


class ClaudeSandboxExecutor:
    """Executor implementation focused on Claude Code workflows.

    Responsibilities:
      - Respect guard verdicts from the secure runtime pipeline.
      - Decide whether to:
          * simulate execution (dryrun),
          * run in a sandbox,
          * or decline to execute.
      - Return a GuardedActionResult suitable for API responses and UI.
    """

    def __init__(
        self,
        config: SandboxExecutorConfig | None = None,
        sandbox_runner: SandboxRunner | None = None,
    ) -> None:
        self._config = config or SandboxExecutorConfig()
        self._runner: SandboxRunner = sandbox_runner or NoopSandboxRunner()

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def mode(self) -> ExecutionMode:
        return self._config.mode

    def _should_use_sandbox(self, action_type: str, target: str) -> bool:
        action = action_type.lower()

        if action == "toolcall" and target.lower() == "shell":
            return self._config.require_sandbox_for_shell

        if action in {"httpfetch", "network"}:
            return self._config.require_sandbox_for_network

        return False

    def _now_iso(self) -> str:
        return datetime.now(UTC).isoformat()

    def execute(
        self,
        ctx: ActionExecutionContext,
        guarded_request: GuardedActionRequest,
    ) -> GuardedActionResult:
        """Execute a guarded action, respecting the guard verdict and executor mode."""
        raw_verdict = getattr(guarded_request, "policy_verdict", None)
        verdict = raw_verdict.strip().lower() if isinstance(raw_verdict, str) else "block"
        should_execute = getattr(guarded_request, "should_execute", None) is True
        halted_by_boundary = getattr(guarded_request, "halted_by_boundary", None)

        if verdict != "allow" or not should_execute or halted_by_boundary is not False:
            return GuardedActionResult(
                execution_state="denied",
                response_action="block",
                response_status="denied",
                policy_verdict="block",
                should_execute=False,
                halted_by_boundary=True,
                executor_name=self.name,
                reason=guarded_request.reason or "Guard policy prevented execution in Claude sandbox executor.",
                raw_result=None,
                started_at=self._now_iso(),
                completed_at=self._now_iso(),
                metadata={
                    "mode": self.mode,
                    "context": ctx.to_dict(),
                },
            )

        execution_state: str
        response_status: str
        raw_result: Any = None

        started_at = self._now_iso()

        if self.mode == "dryrun":
            execution_state = "dryrun"
            response_status = "simulated"
            raw_result = {
                "status": "dryrun",
                "executor": self.name,
                "action_type": guarded_request.action_type,
                "target": guarded_request.target,
            }
        else:
            use_sandbox = self._should_use_sandbox(
                guarded_request.action_type,
                guarded_request.target,
            )

            if self.mode == "sandboxed" and use_sandbox:
                sandbox_result = self._runner.run(
                    guarded_request.action_type,
                    guarded_request.target,
                    guarded_request.content,
                    timeout_seconds=self._config.timeout_seconds,
                    read_only_fs=True,
                    network_enabled=False,
                )
                execution_state = "executed"
                response_status = "completed"
                raw_result = sandbox_result
            else:
                execution_state = "skipped"
                response_status = "bypassed"
                raw_result = {
                    "status": "bypassed",
                    "executor": self.name,
                    "mode": self.mode,
                    "reason": "No sandbox backend configured for this action.",
                }

        completed_at = self._now_iso()

        return GuardedActionResult(
            execution_state=execution_state,
            response_action="allow",
            response_status=response_status,
            policy_verdict="allow",
            should_execute=True,
            halted_by_boundary=False,
            executor_name=self.name,
            reason=guarded_request.reason or "Execution handled by Claude sandbox executor.",
            raw_result=raw_result,
            started_at=started_at,
            completed_at=completed_at,
            metadata={
                "mode": self.mode,
                "context": ctx.to_dict(),
            },
        )
