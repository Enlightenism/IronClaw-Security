from __future__ import annotations

from collections.abc import Callable, MutableMapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.runtime.commandsupervisor import CommandPolicy, build_command_supervisor
from app.runtime.filereturnguard import FileReturnPolicy, build_file_return_guard
from app.runtime.networkguard import NetworkPolicy, build_network_guard

ExecutorCallable = Callable[..., Any]


@dataclass(slots=True)
class SandboxExecutionRequest:
    actiontype: str
    target: str
    command: str | Sequence[str] | None = None
    network_url: str | None = None
    network_method: str = "GET"
    artifact_paths: list[str] = field(default_factory=list)
    content: str | bytes | None = None
    cwd: str | None = None
    timeout_seconds: int = 30
    environment_scope: str = "sandbox"
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "actiontype": self.actiontype,
            "target": self.target,
            "command": self.command,
            "networkurl": self.network_url,
            "networkmethod": self.network_method,
            "artifactpaths": list(self.artifact_paths),
            "cwd": self.cwd,
            "timeoutseconds": int(self.timeout_seconds),
            "environmentscope": self.environment_scope,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class SandboxExecutionDecision:
    executionstate: str
    verdict: str
    allowed: bool
    shouldreview: bool
    shouldblock: bool
    shouldquarantine: bool
    riskdelta: int
    reasons: list[dict[str, Any]] = field(default_factory=list)
    commandsupervision: dict[str, Any] = field(default_factory=dict)
    networkpolicy: dict[str, Any] = field(default_factory=dict)
    artifactpolicies: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "executionstate": self.executionstate,
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.shouldreview,
            "shouldblock": self.shouldblock,
            "shouldquarantine": self.shouldquarantine,
            "riskdelta": int(self.riskdelta),
            "reasons": list(self.reasons),
            "commandsupervision": dict(self.commandsupervision),
            "networkpolicy": dict(self.networkpolicy),
            "artifactpolicies": list(self.artifactpolicies),
        }


@dataclass(slots=True)
class SandboxExecutionResult:
    executionstate: str
    verdict: str
    executed: bool
    result: Any = None
    decision: dict[str, Any] = field(default_factory=dict)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    telemetry: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "executionstate": self.executionstate,
            "verdict": self.verdict,
            "executed": self.executed,
            "result": self.result,
            "decision": dict(self.decision),
            "reasons": list(self.reasons),
            "telemetry": dict(self.telemetry),
        }


@dataclass(slots=True)
class SandboxRouter:
    command_supervisor: Any = field(default_factory=build_command_supervisor)
    network_guard: Any = field(default_factory=build_network_guard)
    file_return_guard: Any = field(default_factory=build_file_return_guard)
    default_executor: ExecutorCallable | None = None
    max_timeout_seconds: int = 300
    name: str = "sandboxrouter"

    def route(
        self,
        *,
        request: SandboxExecutionRequest,
        executor: ExecutorCallable | None = None,
    ) -> SandboxExecutionResult:
        decision = self.evaluate(request=request)

        if not decision.allowed:
            return SandboxExecutionResult(
                executionstate="denied",
                verdict=decision.verdict,
                executed=False,
                result=None,
                decision=decision.as_dict(),
                reasons=list(decision.reasons),
                telemetry=self._build_telemetry(request=request, decision=decision, executed=False),
            )

        runtime_executor = executor or self.default_executor
        if runtime_executor is None:
            return SandboxExecutionResult(
                executionstate="approved",
                verdict=decision.verdict,
                executed=False,
                result=None,
                decision=decision.as_dict(),
                reasons=list(decision.reasons),
                telemetry=self._build_telemetry(request=request, decision=decision, executed=False),
            )

        payload = self._build_executor_payload(request=request, decision=decision)
        result = runtime_executor(**payload)

        return SandboxExecutionResult(
            executionstate="executed",
            verdict=decision.verdict,
            executed=True,
            result=result,
            decision=decision.as_dict(),
            reasons=list(decision.reasons),
            telemetry=self._build_telemetry(request=request, decision=decision, executed=True),
        )

    def evaluate(self, *, request: SandboxExecutionRequest) -> SandboxExecutionDecision:
        normalized_request = self._normalize_request(request)
        reasons: list[dict[str, Any]] = []
        riskdelta = 0

        command_policy = self._evaluate_command_policy(normalized_request)
        if command_policy is not None:
            reasons.extend(command_policy.reasons)
            riskdelta += int(command_policy.risk_delta)

        network_policy = self._evaluate_network_policy(normalized_request)
        if network_policy is not None:
            reasons.extend(network_policy.reasons)
            riskdelta += int(network_policy.risk_delta)

        artifact_policies = self._evaluate_artifact_policies(normalized_request)
        for policy in artifact_policies:
            reasons.extend(policy.reasons)
            riskdelta += int(policy.risk_delta)

        if normalized_request.environment_scope.lower() != "sandbox":
            reasons.append(
                {
                    "source": "sandboxrouter",
                    "label": "Environment boundary",
                    "details": (
                        f"Execution requested environment scope '{normalized_request.environment_scope}' "
                        "outside the default sandbox boundary."
                    ),
                    "score": 45,
                }
            )
            riskdelta += 45

        verdict = "allow"
        executionstate = "approved"
        allowed = True
        shouldreview = False
        shouldblock = False
        shouldquarantine = False

        policies = [policy for policy in (command_policy, network_policy, *artifact_policies) if policy is not None]

        if any(getattr(policy, "should_quarantine", False) for policy in policies):
            verdict = "quarantine"
            executionstate = "denied"
            allowed = False
            shouldblock = True
            shouldquarantine = True
        elif any(getattr(policy, "should_block", False) for policy in policies):
            verdict = "block"
            executionstate = "denied"
            allowed = False
            shouldblock = True
        elif any(getattr(policy, "should_review", False) for policy in policies):
            verdict = "review"
            executionstate = "queuedforreview"
            shouldreview = True

        normalized_risk = max(0, min(100, int(riskdelta)))

        reasons.insert(
            0,
            {
                "source": "sandboxrouter",
                "label": "Sandbox routing",
                "details": (
                    f"Sandbox router evaluated action '{normalized_request.actiontype}' "
                    f"for target '{normalized_request.target}' with cumulative risk {normalized_risk}."
                ),
                "score": normalized_risk,
            },
        )

        return SandboxExecutionDecision(
            executionstate=executionstate,
            verdict=verdict,
            allowed=allowed,
            shouldreview=shouldreview,
            shouldblock=shouldblock,
            shouldquarantine=shouldquarantine,
            riskdelta=normalized_risk,
            reasons=reasons,
            commandsupervision=command_policy.as_dict() if command_policy is not None else {},
            networkpolicy=network_policy.as_dict() if network_policy is not None else {},
            artifactpolicies=[policy.as_dict() for policy in artifact_policies],
        )

    def _normalize_request(self, request: SandboxExecutionRequest) -> SandboxExecutionRequest:
        timeout_seconds = max(1, min(int(request.timeout_seconds), int(self.max_timeout_seconds)))
        metadata = dict(request.metadata or {})
        metadata.setdefault("router", self.name)
        metadata.setdefault("environment_scope", request.environment_scope)

        return SandboxExecutionRequest(
            actiontype=str(request.actiontype or "").strip().lower(),
            target=str(request.target or "").strip().lower(),
            command=request.command,
            network_url=str(request.network_url or "").strip() or None,
            network_method=str(request.network_method or "GET").upper(),
            artifact_paths=[str(item).strip() for item in request.artifact_paths if str(item).strip()],
            content=request.content,
            cwd=str(request.cwd).strip() if request.cwd else None,
            timeout_seconds=timeout_seconds,
            environment_scope=str(request.environment_scope or "sandbox").strip(),
            metadata=metadata,
        )

    def _evaluate_command_policy(self, request: SandboxExecutionRequest) -> CommandPolicy | None:
        if request.command is None:
            return None
        return self.command_supervisor.evaluate(
            command=request.command,
            actiontype=request.actiontype,
            target=request.target,
            cwd=request.cwd,
            metadata={
                **dict(request.metadata),
                "environment_scope": request.environment_scope,
            },
        )

    def _evaluate_network_policy(self, request: SandboxExecutionRequest) -> NetworkPolicy | None:
        if not request.network_url:
            return None
        return self.network_guard.evaluate(
            url=request.network_url,
            method=request.network_method,
            metadata={
                **dict(request.metadata),
                "direction": "egress",
            },
        )

    def _evaluate_artifact_policies(self, request: SandboxExecutionRequest) -> list[FileReturnPolicy]:
        policies: list[FileReturnPolicy] = []
        for artifact_path in request.artifact_paths:
            policies.append(
                self.file_return_guard.evaluate(
                    path=artifact_path,
                    content=request.content,
                    metadata=request.metadata,
                )
            )
        return policies

    def _build_executor_payload(
        self,
        *,
        request: SandboxExecutionRequest,
        decision: SandboxExecutionDecision,
    ) -> dict[str, Any]:
        payload: MutableMapping[str, Any] = {
            "actiontype": request.actiontype,
            "target": request.target,
            "timeout_seconds": request.timeout_seconds,
            "cwd": request.cwd,
            "environment_scope": request.environment_scope,
            "metadata": {
                **dict(request.metadata),
                "sandboxdecision": decision.as_dict(),
            },
        }
        if request.command is not None:
            payload["command"] = request.command
        if request.network_url is not None:
            payload["network_url"] = request.network_url
            payload["network_method"] = request.network_method
        if request.artifact_paths:
            payload["artifact_paths"] = list(request.artifact_paths)
        if request.content is not None:
            payload["content"] = request.content
        return dict(payload)

    def _build_telemetry(
        self,
        *,
        request: SandboxExecutionRequest,
        decision: SandboxExecutionDecision,
        executed: bool,
    ) -> dict[str, Any]:
        return {
            "router": self.name,
            "actiontype": request.actiontype,
            "target": request.target,
            "executed": executed,
            "timeoutseconds": int(request.timeout_seconds),
            "environmentscope": request.environment_scope,
            "artifactcount": len(request.artifact_paths),
            "hascommand": request.command is not None,
            "hasnetwork": bool(request.network_url),
            "verdict": decision.verdict,
            "riskdelta": int(decision.riskdelta),
        }


def initialize_sandboxrouter(
    *,
    command_supervisor: Any | None = None,
    network_guard: Any | None = None,
    file_return_guard: Any | None = None,
    default_executor: ExecutorCallable | None = None,
    max_timeout_seconds: int = 300,
) -> SandboxRouter:
    return SandboxRouter(
        command_supervisor=command_supervisor or build_command_supervisor(),
        network_guard=network_guard or build_network_guard(),
        file_return_guard=file_return_guard or build_file_return_guard(),
        default_executor=default_executor,
        max_timeout_seconds=max_timeout_seconds,
    )


def build_sandbox_router() -> SandboxRouter:
    return initialize_sandboxrouter()