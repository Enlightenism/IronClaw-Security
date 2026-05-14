from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from orchestrator.executionplan import ExecutionPlan

from orchestrator.policyenforcer import EnforcementContext
from orchestrator.responsecoordinator import CoordinatedResponse, ResponseOutcome
from orchestrator.reviewqueue import ReviewQueue, ReviewQueueItem
from orchestrator.secureruntimepipeline import RuntimeExecutionResult, SecureRuntimePipeline
from orchestrator.supervisor import SupervisorDecision, SupervisorStatus


@dataclass(slots=True)
class OrchestrationRequest:
    request_id: str
    action: str
    target: str = "runtime"
    payload: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    source: str | None = None
    actor_id: str | None = None
    session_id: str | None = None
    organization_id: str | None = None
    requires_network: bool = False
    requires_filesystem: bool = False
    requires_secrets: bool = False
    requires_human_review: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> OrchestrationRequest:
        payload = dict(data or {})
        return cls(
            request_id=str(payload.get("request_id") or f"req-{uuid4().hex}"),
            action=str(payload.get("action") or "execute"),
            target=str(payload.get("target") or "runtime"),
            payload=dict(payload.get("payload") or payload.get("attributes") or {}),
            risk_score=int(payload.get("risk_score") or 0),
            source=payload.get("source"),
            actor_id=payload.get("actor_id"),
            session_id=payload.get("session_id"),
            organization_id=payload.get("organization_id"),
            requires_network=bool(payload.get("requires_network", False)),
            requires_filesystem=bool(payload.get("requires_filesystem", False)),
            requires_secrets=bool(payload.get("requires_secrets", False)),
            requires_human_review=bool(payload.get("requires_human_review", False)),
            metadata=dict(payload.get("metadata") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "action": self.action,
            "target": self.target,
            "payload": dict(self.payload),
            "risk_score": self.risk_score,
            "source": self.source,
            "actor_id": self.actor_id,
            "session_id": self.session_id,
            "organization_id": self.organization_id,
            "requires_network": self.requires_network,
            "requires_filesystem": self.requires_filesystem,
            "requires_secrets": self.requires_secrets,
            "requires_human_review": self.requires_human_review,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class OrchestrationStep:
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
class OrchestrationResult:
    orchestration_id: str
    request_id: str
    status: str
    outcome: str
    allowed: bool
    plan: dict[str, Any]
    runtime: dict[str, Any]
    coordination: dict[str, Any]
    review: dict[str, Any] | None = None
    steps: list[OrchestrationStep] = field(default_factory=list)
    telemetry: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str | None = None

    def finalize(self) -> OrchestrationResult:
        self.completed_at = datetime.now(UTC).isoformat()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "orchestration_id": self.orchestration_id,
            "request_id": self.request_id,
            "status": self.status,
            "outcome": self.outcome,
            "allowed": self.allowed,
            "plan": dict(self.plan),
            "runtime": dict(self.runtime),
            "coordination": dict(self.coordination),
            "review": dict(self.review) if self.review else None,
            "steps": [step.to_dict() for step in self.steps],
            "telemetry": [dict(event) for event in self.telemetry],
            "metadata": dict(self.metadata),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class Orchestrator:
    def __init__(
        self,
        *,
        runtime_pipeline: SecureRuntimePipeline | None = None,
        review_queue: ReviewQueue | None = None,
    ) -> None:
        self.runtime_pipeline = runtime_pipeline or SecureRuntimePipeline()
        self.review_queue = review_queue or ReviewQueue()

    def orchestrate(self, request: OrchestrationRequest | Mapping[str, Any] | None) -> OrchestrationResult:
        normalized_request = request if isinstance(request, OrchestrationRequest) else OrchestrationRequest.from_mapping(request)

        result = OrchestrationResult(
            orchestration_id=f"orch-{uuid4().hex}",
            request_id=normalized_request.request_id,
            status="initializing",
            outcome="unknown",
            allowed=False,
            plan=self._build_plan(normalized_request),
            runtime={},
            coordination={},
            metadata={
                "target": normalized_request.target,
                "action": normalized_request.action,
                "risk_score": normalized_request.risk_score,
            },
        )

        self._record_step(
            result,
            name="plan_created",
            status="completed",
            message="Execution plan created for orchestration.",
            details={"plan_id": result.plan["plan_id"]},
        )

        enforcement_context = EnforcementContext.create(
            request_id=normalized_request.request_id,
            source=normalized_request.source,
            actor_id=normalized_request.actor_id,
            session_id=normalized_request.session_id,
            organization_id=normalized_request.organization_id,
            metadata=dict(normalized_request.metadata),
        )

        runtime_result = self.runtime_pipeline.run(
            self._build_runtime_request(normalized_request),
            context=enforcement_context,
        )
        result.runtime = runtime_result.to_dict()

        self._record_step(
            result,
            name="runtime_pipeline",
            status=runtime_result.status,
            message="Secure runtime pipeline completed.",
            details={
                "execution_id": runtime_result.execution_id,
                "verdict": runtime_result.verdict,
                "allowed": runtime_result.allowed,
            },
        )

        coordination = self._build_coordination(runtime_result)
        result.coordination = coordination.to_dict()
        result.outcome = coordination.outcome.value
        result.allowed = coordination.allow

        self._record_step(
            result,
            name="response_coordinated",
            status="completed",
            message="Runtime response coordinated into final orchestration outcome.",
            details={
                "response_id": coordination.response_id,
                "outcome": coordination.outcome.value,
            },
        )

        if coordination.review_required:
            review_item = self._enqueue_review(normalized_request, coordination, runtime_result)
            result.review = review_item.to_dict()
            result.status = "needs_review"
            self._record_step(
                result,
                name="review_queued",
                status="queued",
                message="Request has been placed into the human review queue.",
                details={"review_id": review_item.review_id},
            )
        elif coordination.quarantine_required:
            result.status = "quarantined"
        elif coordination.allow:
            result.status = "completed"
        else:
            result.status = "blocked"

        self._emit_telemetry(result, event=f"orchestrator.{result.status}")
        return result.finalize()

    def orchestrate_dict(self, request: OrchestrationRequest | Mapping[str, Any] | None) -> dict[str, Any]:
        return self.orchestrate(request).to_dict()

    def _build_plan(self, request: OrchestrationRequest) -> dict[str, Any]:
        plan = ExecutionPlan(
            plan_id=f"plan-{uuid4().hex}",
            request_id=request.request_id,
            target=request.target,
            action=request.action,
            steps=[
                "policy_enforcement",
                "pre_execution_guards",
                "runtime_execution",
                "response_coordination",
            ],
            metadata={
                "risk_score": request.risk_score,
                "requires_network": request.requires_network,
                "requires_filesystem": request.requires_filesystem,
                "requires_secrets": request.requires_secrets,
                "requires_human_review": request.requires_human_review,
            },
        )
        return plan.to_dict()

    def _build_runtime_request(self, request: OrchestrationRequest) -> dict[str, Any]:
        return {
            "request_id": request.request_id,
            "target": request.target,
            "action": request.action,
            "risk_score": request.risk_score,
            "attributes": dict(request.payload),
            "source": request.source,
            "actor_id": request.actor_id,
            "session_id": request.session_id,
            "organization_id": request.organization_id,
            "requires_network": request.requires_network,
            "requires_filesystem": request.requires_filesystem,
            "requires_secrets": request.requires_secrets,
            "requires_human_review": request.requires_human_review,
        }

    def _build_coordination(self, runtime_result: RuntimeExecutionResult) -> CoordinatedResponse:
        review_required = runtime_result.status == "needs_review" or any(step.name == "human_review" for step in runtime_result.steps)
        quarantine_required = runtime_result.status == "quarantined"
        blocked = runtime_result.status == "blocked" or not runtime_result.allowed

        if quarantine_required:
            outcome = ResponseOutcome.QUARANTINE
        elif review_required:
            outcome = ResponseOutcome.NEEDS_REVIEW
        elif blocked:
            outcome = ResponseOutcome.BLOCK
        elif runtime_result.verdict == "warn":
            outcome = ResponseOutcome.ALLOW_WITH_CONTROLS
        else:
            outcome = ResponseOutcome.ALLOW

        gate = {
            "status": "completed",
            "decision": "approved" if runtime_result.allowed else "restricted",
            "actions": runtime_result.enforcement.actions,
        }
        supervisor = {
            "status": SupervisorStatus.ACTIVE.value,
            "decision": SupervisorDecision.APPROVE.value if runtime_result.allowed else SupervisorDecision.REJECT.value,
            "message": "Supervisor evaluated runtime outcome.",
        }
        session = {
            "session_id": runtime_result.enforcement.context.session_id or f"session-{uuid4().hex}",
            "status": "active" if runtime_result.allowed else "restricted",
            "request_id": runtime_result.request_id,
        }

        return CoordinatedResponse(
            response_id=f"resp-{uuid4().hex}",
            request_id=runtime_result.request_id,
            session_id=session["session_id"],
            outcome=outcome,
            gate=gate,
            supervisor=supervisor,
            session=session,
            allow=runtime_result.allowed and outcome not in {ResponseOutcome.BLOCK, ResponseOutcome.QUARANTINE},
            sandbox_required=runtime_result.verdict == "warn",
            redaction_required=False,
            quarantine_required=quarantine_required,
            review_required=review_required,
            review_id=f"review-{uuid4().hex}" if review_required else None,
            quarantine_id=f"quarantine-{uuid4().hex}" if quarantine_required else None,
            steps=[],
        )

    def _enqueue_review(
        self,
        request: OrchestrationRequest,
        coordination: CoordinatedResponse,
        runtime_result: RuntimeExecutionResult,
    ) -> ReviewQueueItem:
        return self.review_queue.enqueue(
            {
                "review_id": coordination.review_id or f"review-{uuid4().hex}",
                "request_id": request.request_id,
                "category": "runtime_execution",
                "severity": "high" if request.risk_score >= 70 else "medium",
                "status": "queued",
                "payload": {
                    "request": request.to_dict(),
                    "runtime": runtime_result.to_dict(),
                    "coordination": coordination.to_dict(),
                },
            },
        )

    def _record_step(
        self,
        result: OrchestrationResult,
        *,
        name: str,
        status: str,
        message: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        result.steps.append(
            OrchestrationStep(
                name=name,
                status=status,
                message=message,
                details=dict(details or {}),
            ),
        )

    def _emit_telemetry(self, result: OrchestrationResult, *, event: str) -> None:
        result.telemetry.append(
            {
                "event_id": f"tel-{uuid4().hex}",
                "event": event,
                "timestamp": datetime.now(UTC).isoformat(),
                "orchestration_id": result.orchestration_id,
                "request_id": result.request_id,
                "status": result.status,
                "outcome": result.outcome,
                "allowed": result.allowed,
            },
        )


def orchestrate_request(
    request: OrchestrationRequest | Mapping[str, Any] | None,
    *,
    orchestrator: Orchestrator | None = None,
) -> OrchestrationResult:
    active_orchestrator = orchestrator or Orchestrator()
    return active_orchestrator.orchestrate(request)


def orchestrate_request_dict(
    request: OrchestrationRequest | Mapping[str, Any] | None,
    *,
    orchestrator: Orchestrator | None = None,
) -> dict[str, Any]:
    return orchestrate_request(request, orchestrator=orchestrator).to_dict()


__all__ = [
    "OrchestrationRequest",
    "OrchestrationResult",
    "OrchestrationStep",
    "Orchestrator",
    "orchestrate_request",
    "orchestrate_request_dict",
]
