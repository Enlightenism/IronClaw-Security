from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
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

        decision = result.enforcement.decision
        decision_score_is_valid = isinstance(decision.risk_score, int) and not isinstance(decision.risk_score, bool) and 0 <= decision.risk_score <= 100
        decision_score = decision.risk_score if decision_score_is_valid else RISK_THRESHOLD_BLOCK_MIN
        should_block = (
            decision.verdict != PolicyVerdict.ALLOW
            or decision.allowed is not True
            or bool(decision.matched_rules)
            or decision.requires_human_review
            or not decision_score_is_valid
            or decision_score > RISK_THRESHOLD_ALLOW_MAX
            or result.enforcement.blocked
            or result.enforcement.quarantine_required
            or result.enforcement.review_required
        )
        if should_block:
            self._mark_blocked(
                result,
                ("Secure runtime pipeline blocked a non-allow or invalid policy decision." if not decision.reasons else ""),
            )
        else:
            result.verdict = PolicyVerdict.ALLOW.value
            result.allowed = True
            decision.verdict = PolicyVerdict.ALLOW
            decision.allowed = True
            decision.risk_score = decision_score
        result.runtime_metadata["risk_score"] = decision.risk_score

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

        if result.enforcement.review_required:
            self._record_step(
                result,
                name="human_review",
                status="pending",
                message="Execution requires human review before unrestricted completion.",
                details={"review_required": True},
            )

        if result.verdict == PolicyVerdict.BLOCK.value:
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

        self._run_pre_execution_guards(result, normalized_request)

        if result.status == "blocked":
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

        result.status = "completed"
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
            if result.status == "blocked":
                return

        if request.requires_filesystem:
            guard_result = self._invoke_guard(self.filesystem_guard, request, guard_name="filesystem_guard")
            self._apply_guard_result(result, guard_result, default_name="filesystem_guard")
            if result.status == "blocked":
                return

        if request.requires_secrets:
            guard_result = self._invoke_guard(self.secrets_guard, request, guard_name="secrets_guard")
            self._apply_guard_result(result, guard_result, default_name="secrets_guard")
            if result.status == "blocked":
                return

        if result.status != "blocked":
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

        try:
            payload = guard(request)
        except Exception as exc:
            return {
                "name": guard_name,
                "status": "blocked",
                "message": f"{guard_name} failed; runtime execution is blocked.",
                "action": "block",
                "details": {"error_type": type(exc).__name__},
            }

        if not isinstance(payload, Mapping):
            return {
                "name": guard_name,
                "status": "blocked",
                "message": f"{guard_name} returned no valid decision; runtime execution is blocked.",
                "action": "block",
            }
        raw_action = payload.get("action")
        status = str(payload.get("status") or "")
        status_value = status.strip().lower()
        action = (
            "allow"
            if raw_action == "allow"
            and status_value
            not in {
                "error",
                "failed",
                "failure",
                "blocked",
                "denied",
                "warn",
                "warning",
                "quarantine",
                "quarantined",
            }
            else "block"
        )
        raw_details = payload.get("details")
        return {
            "name": payload.get("name", guard_name),
            "status": "passed" if action == "allow" else "blocked",
            "message": payload.get("message", f"{guard_name} completed."),
            "action": action,
            "details": dict(raw_details) if isinstance(raw_details, Mapping) else {},
        }

    def _apply_guard_result(
        self,
        result: RuntimeExecutionResult,
        guard_result: Mapping[str, Any],
        *,
        default_name: str,
    ) -> None:
        name = str(guard_result.get("name") or default_name)
        status = str(guard_result.get("status") or "blocked")
        message = str(guard_result.get("message") or f"{name} completed.")
        action = "allow" if guard_result.get("action") == "allow" else "block"
        details = dict(guard_result.get("details") or {})
        details["guard_action"] = action

        if action == "block":
            status = "blocked"
            self._mark_blocked(
                result,
                message or f"{name} blocked runtime execution.",
            )
            self._record_step(
                result,
                name=f"{name}_halt",
                status="blocked",
                message=f"{name} blocked runtime execution.",
                details={"reason": action},
            )
        self._record_step(
            result,
            name=name,
            status=status,
            message=message,
            details=details,
        )

    def _mark_blocked(
        self,
        result: RuntimeExecutionResult,
        reason: str,
    ) -> None:
        decision = result.enforcement.decision
        risk_score = decision.risk_score
        if not isinstance(risk_score, int) or isinstance(risk_score, bool) or not 0 <= risk_score <= 100:
            risk_score = RISK_THRESHOLD_BLOCK_MIN

        result.status = "blocked"
        result.verdict = PolicyVerdict.BLOCK.value
        result.allowed = False
        decision.verdict = PolicyVerdict.BLOCK
        decision.allowed = False
        decision.risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)
        if reason and reason not in decision.reasons:
            decision.reasons.append(reason)
        result.enforcement.status = "blocked"
        result.enforcement.blocked = True
        result.enforcement.review_required = result.enforcement.review_required or decision.requires_human_review
        result.enforcement.quarantine_required = False
        result.enforcement.actions = [
            action_name
            for action_name in result.enforcement.actions
            if action_name
            not in {
                "allow_execution",
                "allow_with_warning",
                "emit_security_warning",
                "quarantine_request",
            }
        ]
        for action_name in ("block_request", "halt_execution", "preserve_evidence"):
            if action_name not in result.enforcement.actions:
                result.enforcement.actions.append(action_name)
        if result.enforcement.review_required and "enqueue_review" not in result.enforcement.actions:
            result.enforcement.actions.append("enqueue_review")
        result.runtime_metadata["risk_score"] = decision.risk_score
        result.enforcement.metadata["risk_score"] = decision.risk_score
        result.enforcement.audit_record.update(
            status="blocked",
            verdict=PolicyVerdict.BLOCK.value,
            risk_score=decision.risk_score,
            actions=list(result.enforcement.actions),
            reasons=list(decision.reasons),
            review_required=result.enforcement.review_required,
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
