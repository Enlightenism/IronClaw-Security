from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from orchestrator.policyenforcer import (
    EnforcementContext,
    EnforcementResult,
    PolicyEnforcer,
    build_policy_request,
)
from orchestrator.policyengine import PolicyRequest, PolicyTarget, PolicyVerdict


@dataclass(slots=True)
class RuntimeStep:
    name: str
    status: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "details": dict(self.details),
            "timestamp": self.timestamp,
        }


@dataclass(slots=True)
class RuntimeArtifact:
    artifact_id: str
    kind: str
    value: Any
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "value": self.value,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class RuntimeExecutionResult:
    execution_id: str
    request_id: str
    status: str
    verdict: str
    allowed: bool
    enforcement: EnforcementResult
    steps: list[RuntimeStep] = field(default_factory=list)
    artifacts: list[RuntimeArtifact] = field(default_factory=list)
    telemetry: list[dict[str, Any]] = field(default_factory=list)
    runtime_metadata: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str | None = None

    def finalize(self) -> RuntimeExecutionResult:
        self.completed_at = datetime.now(UTC).isoformat()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "request_id": self.request_id,
            "status": self.status,
            "verdict": self.verdict,
            "allowed": self.allowed,
            "enforcement": self.enforcement.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "telemetry": [dict(item) for item in self.telemetry],
            "runtime_metadata": dict(self.runtime_metadata),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class SecureRuntimePipeline:
    def __init__(
        self,
        policy_enforcer: PolicyEnforcer | None = None,
        *,
        network_guard: Callable[[PolicyRequest], Mapping[str, Any] | None] | None = None,
        filesystem_guard: Callable[[PolicyRequest], Mapping[str, Any] | None] | None = None,
        secrets_guard: Callable[[PolicyRequest], Mapping[str, Any] | None] | None = None,
        executor: Callable[[PolicyRequest], Mapping[str, Any] | None] | None = None,
        telemetry_sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.policy_enforcer = policy_enforcer or PolicyEnforcer()
        self.network_guard = network_guard
        self.filesystem_guard = filesystem_guard
        self.secrets_guard = secrets_guard
        self.executor = executor
        self.telemetry_sink = telemetry_sink

    def run(
        self,
        request: PolicyRequest | Mapping[str, Any] | None,
        *,
        context: EnforcementContext | Mapping[str, Any] | None = None,
    ) -> RuntimeExecutionResult:
        normalized_request = request if isinstance(request, PolicyRequest) else PolicyRequest.from_mapping(request)
        normalized_context = self._normalize_context(context, normalized_request)

        result = RuntimeExecutionResult(
            execution_id=f"run-{uuid4().hex}",
            request_id=normalized_context.request_id,
            status="initializing",
            verdict="unknown",
            allowed=False,
            enforcement=self.policy_enforcer.enforce(normalized_request, context=normalized_context),
            runtime_metadata={
                "target": normalized_request.target.value,
                "action": normalized_request.action,
                "risk_score": normalized_request.risk_score,
            },
        )

        result.verdict = result.enforcement.decision.verdict.value
        result.allowed = result.enforcement.decision.allowed

        self._record_step(
            result,
            name="policy_enforcement",
            status=result.enforcement.status,
            message="Policy enforcement completed.",
            details={
                "verdict": result.enforcement.decision.verdict.value,
                "matched_rules": result.enforcement.decision.matched_rules,
                "actions": result.enforcement.actions,
            },
        )

        if result.enforcement.blocked:
            result.status = "blocked"
            self._record_step(
                result,
                name="runtime_halt",
                status="blocked",
                message="Execution halted because the request was blocked.",
                details={"reason": "policy_block"},
            )
            self._emit_telemetry(result, event="runtime.blocked")
            return result.finalize()

        if result.enforcement.quarantine_required:
            result.status = "quarantined"
            self._record_step(
                result,
                name="runtime_quarantine",
                status="quarantined",
                message="Execution diverted into quarantine.",
                details={"reason": "policy_quarantine"},
            )
            self._emit_telemetry(result, event="runtime.quarantined")
            return result.finalize()

        if result.enforcement.review_required:
            self._record_step(
                result,
                name="human_review",
                status="pending",
                message="Execution requires human review before unrestricted completion.",
                details={"review_required": True},
            )

        self._run_pre_execution_guards(result, normalized_request)

        if result.status in {"blocked", "quarantined"}:
            self._emit_telemetry(result, event=f"runtime.{result.status}")
            return result.finalize()

        execution_payload = self._execute(normalized_request, result)

        artifact = RuntimeArtifact(
            artifact_id=f"art-{uuid4().hex}",
            kind="execution_result",
            value=execution_payload.get("result"),
            metadata={
                "executor_status": execution_payload.get("status", "completed"),
                "executor_message": execution_payload.get("message", "Execution finished."),
            },
        )
        result.artifacts.append(artifact)

        self._record_step(
            result,
            name="executor",
            status=execution_payload.get("status", "completed"),
            message=execution_payload.get("message", "Execution finished."),
            details={
                "has_result": "result" in execution_payload,
                "artifact_id": artifact.artifact_id,
            },
        )

        result.status = "completed_with_warnings" if result.enforcement.decision.verdict == PolicyVerdict.WARN else "completed"
        self._emit_telemetry(result, event="runtime.completed")
        return result.finalize()

    def run_dict(
        self,
        request: PolicyRequest | Mapping[str, Any] | None,
        *,
        context: EnforcementContext | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.run(request, context=context).to_dict()

    def run_batch(
        self,
        requests: Iterable[PolicyRequest | Mapping[str, Any] | None],
        *,
        context_factory: Callable[[int, PolicyRequest], EnforcementContext | Mapping[str, Any] | None] | None = None,
    ) -> list[RuntimeExecutionResult]:
        results: list[RuntimeExecutionResult] = []
        for index, item in enumerate(requests):
            normalized_request = item if isinstance(item, PolicyRequest) else PolicyRequest.from_mapping(item)
            context = context_factory(index, normalized_request) if context_factory else None
            results.append(self.run(normalized_request, context=context))
        return results

    def _normalize_context(
        self,
        context: EnforcementContext | Mapping[str, Any] | None,
        request: PolicyRequest,
    ) -> EnforcementContext:
        if isinstance(context, EnforcementContext):
            return context

        payload = dict(context or {})
        return EnforcementContext.create(
            request_id=payload.get("request_id"),
            source=payload.get("source") or request.source,
            actor_id=payload.get("actor_id") or request.actor_id,
            session_id=payload.get("session_id") or request.session_id,
            organization_id=payload.get("organization_id") or request.organization_id,
            trace_id=payload.get("trace_id"),
            metadata=payload.get("metadata") or {},
        )

    def _run_pre_execution_guards(self, result: RuntimeExecutionResult, request: PolicyRequest) -> None:
        self._record_step(
            result,
            name="preflight",
            status="running",
            message="Pre-execution runtime guards are evaluating the request.",
            details={},
        )

        if request.requires_network:
            guard_result = self._invoke_guard(self.network_guard, request, guard_name="network_guard")
            self._apply_guard_result(result, guard_result, default_name="network_guard")

        if request.requires_filesystem:
            guard_result = self._invoke_guard(self.filesystem_guard, request, guard_name="filesystem_guard")
            self._apply_guard_result(result, guard_result, default_name="filesystem_guard")

        if request.requires_secrets:
            guard_result = self._invoke_guard(self.secrets_guard, request, guard_name="secrets_guard")
            self._apply_guard_result(result, guard_result, default_name="secrets_guard")

        if result.status not in {"blocked", "quarantined"}:
            self._record_step(
                result,
                name="preflight_complete",
                status="passed",
                message="All configured runtime guards passed.",
                details={},
            )

    def _invoke_guard(
        self,
        guard: Callable[[PolicyRequest], Mapping[str, Any] | None] | None,
        request: PolicyRequest,
        *,
        guard_name: str,
    ) -> dict[str, Any]:
        if guard is None:
            return {
                "name": guard_name,
                "status": "passed",
                "message": f"{guard_name} passed using default pipeline behavior.",
                "action": "allow",
            }

        payload = guard(request) or {}
        return {
            "name": payload.get("name", guard_name),
            "status": payload.get("status", "passed"),
            "message": payload.get("message", f"{guard_name} completed."),
            "action": payload.get("action", "allow"),
            "details": dict(payload.get("details") or {}),
        }

    def _apply_guard_result(
        self,
        result: RuntimeExecutionResult,
        guard_result: Mapping[str, Any],
        *,
        default_name: str,
    ) -> None:
        name = str(guard_result.get("name") or default_name)
        status = str(guard_result.get("status") or "passed")
        message = str(guard_result.get("message") or f"{name} completed.")
        action = str(guard_result.get("action") or "allow")
        details = dict(guard_result.get("details") or {})
        details["guard_action"] = action

        self._record_step(result, name=name, status=status, message=message, details=details)

        if action == "block":
            result.status = "blocked"
            result.allowed = False
            self._record_step(
                result,
                name=f"{name}_halt",
                status="blocked",
                message=f"{name} blocked runtime execution.",
                details={"reason": action},
            )

        if action == "quarantine":
            result.status = "quarantined"
            result.allowed = False
            self._record_step(
                result,
                name=f"{name}_containment",
                status="quarantined",
                message=f"{name} quarantined runtime execution.",
                details={"reason": action},
            )

        if action == "warn" and result.status not in {"blocked", "quarantined"}:
            if result.status == "initializing":
                result.status = "warning"
            self._record_step(
                result,
                name=f"{name}_warning",
                status="warned",
                message=f"{name} raised a runtime warning.",
                details={"reason": action},
            )

    def _execute(self, request: PolicyRequest, result: RuntimeExecutionResult) -> dict[str, Any]:
        self._record_step(
            result,
            name="execution_start",
            status="running",
            message="Runtime execution has started.",
            details={"action": request.action, "target": request.target.value},
        )

        if self.executor is None:
            return {
                "status": "completed",
                "message": "Default secure runtime execution completed.",
                "result": {
                    "action": request.action,
                    "target": request.target.value,
                    "attributes": dict(request.attributes),
                    "runtime_mode": "default",
                },
            }

        payload = self.executor(request) or {}
        return {
            "status": payload.get("status", "completed"),
            "message": payload.get("message", "Custom executor completed."),
            "result": payload.get(
                "result",
                {
                    "action": request.action,
                    "target": request.target.value,
                    "attributes": dict(request.attributes),
                    "runtime_mode": "custom",
                },
            ),
        }

    def _record_step(
        self,
        result: RuntimeExecutionResult,
        *,
        name: str,
        status: str,
        message: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        step = RuntimeStep(
            name=name,
            status=status,
            message=message,
            details=dict(details or {}),
        )
        result.steps.append(step)

    def _emit_telemetry(self, result: RuntimeExecutionResult, *, event: str) -> None:
        telemetry_event = {
            "event_id": f"tel-{uuid4().hex}",
            "event": event,
            "timestamp": datetime.now(UTC).isoformat(),
            "execution_id": result.execution_id,
            "request_id": result.request_id,
            "status": result.status,
            "verdict": result.verdict,
            "allowed": result.allowed,
            "step_count": len(result.steps),
            "artifact_count": len(result.artifacts),
        }
        result.telemetry.append(telemetry_event)
        if self.telemetry_sink is not None:
            self.telemetry_sink(telemetry_event)


def run_secure_runtime(
    request: PolicyRequest | Mapping[str, Any] | None,
    *,
    context: EnforcementContext | Mapping[str, Any] | None = None,
    pipeline: SecureRuntimePipeline | None = None,
) -> RuntimeExecutionResult:
    active_pipeline = pipeline or SecureRuntimePipeline()
    return active_pipeline.run(request, context=context)


def run_secure_runtime_dict(
    request: PolicyRequest | Mapping[str, Any] | None,
    *,
    context: EnforcementContext | Mapping[str, Any] | None = None,
    pipeline: SecureRuntimePipeline | None = None,
) -> dict[str, Any]:
    return run_secure_runtime(request, context=context, pipeline=pipeline).to_dict()


def build_runtime_request(
    *,
    target: PolicyTarget | str = PolicyTarget.RUNTIME,
    action: str = "execute",
    risk_score: int = 0,
    attributes: Mapping[str, Any] | None = None,
    source: str | None = None,
    actor_id: str | None = None,
    session_id: str | None = None,
    organization_id: str | None = None,
    requires_network: bool = False,
    requires_filesystem: bool = False,
    requires_secrets: bool = False,
    requires_human_review: bool = False,
    fail_closed: bool = True,
) -> PolicyRequest:
    return build_policy_request(
        target=target,
        action=action,
        risk_score=risk_score,
        attributes=attributes,
        source=source,
        actor_id=actor_id,
        session_id=session_id,
        organization_id=organization_id,
        requires_network=requires_network,
        requires_filesystem=requires_filesystem,
        requires_secrets=requires_secrets,
        requires_human_review=requires_human_review,
        fail_closed=fail_closed,
    )


__all__ = [
    "RuntimeArtifact",
    "RuntimeExecutionResult",
    "RuntimeStep",
    "SecureRuntimePipeline",
    "build_runtime_request",
    "run_secure_runtime",
    "run_secure_runtime_dict",
]