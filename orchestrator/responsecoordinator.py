from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from orchestrator.remediationgate import GateDecision, GateStatus, RemediationAction
from orchestrator.runtimesession import RuntimeSession, RuntimeSessionManager, RuntimeSessionStatus
from orchestrator.supervisor import SupervisorDecision, SupervisorStatus


class ResponseOutcome(StrEnum):
    ALLOW = "allow"
    ALLOW_WITH_SANDBOX = "allow_with_sandbox"
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    ALLOW_WITH_CONTROLS = "allow_with_controls"
    NEEDS_REVIEW = "needs_review"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    FAILED = "failed"


@dataclass(slots=True)
class ResponseStep:
    step_id: str
    kind: str
    status: str
    message: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "kind": self.kind,
            "status": self.status,
            "message": self.message,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class CoordinatedResponse:
    response_id: str
    request_id: str
    session_id: str
    outcome: ResponseOutcome
    gate: dict[str, Any]
    supervisor: dict[str, Any]
    session: dict[str, Any]
    allow: bool
    sandbox_required: bool
    redaction_required: bool
    quarantine_required: bool
    review_required: bool
    review_id: str | None = None
    quarantine_id: str | None = None
    steps: list[ResponseStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def add_step(self, kind: str, status: str, message: str, metadata: Mapping[str, Any] | None = None) -> None:
        self.steps.append(
            ResponseStep(
                step_id=f"step-{uuid4().hex}",
                kind=kind,
                status=status,
                message=message,
                metadata=dict(metadata or {}),
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "response_id": self.response_id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "outcome": self.outcome.value,
            "allow": self.allow,
            "sandbox_required": self.sandbox_required,
            "redaction_required": self.redaction_required,
            "quarantine_required": self.quarantine_required,
            "review_required": self.review_required,
            "review_id": self.review_id,
            "quarantine_id": self.quarantine_id,
            "gate": dict(self.gate),
            "supervisor": dict(self.supervisor),
            "session": dict(self.session),
            "steps": [step.to_dict() for step in self.steps],
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


class ResponseCoordinator:
    """ResponseCoordinator is the single place that turns lower-level decisions
    (gate, supervisor, runtime session) into one coherent response envelope
    for the secure runtime pipeline.
    """

    def __init__(self, session_manager: RuntimeSessionManager | None = None) -> None:
        self.session_manager = session_manager or RuntimeSessionManager()

    def coordinate(
        self,
        *,
        request: Mapping[str, Any],
        gate: GateDecision,
        supervisor: SupervisorDecision,
        session: RuntimeSession | None = None,
    ) -> CoordinatedResponse:
        base_request: MutableMapping[str, Any] = dict(request or {})
        request_id = str(base_request.get("request_id") or gate.request_id or supervisor.request_id or f"req-{uuid4().hex}")

        if session is None:
            session = self.session_manager.start(
                {
                    "request_id": request_id,
                    "actor_id": base_request.get("actor_id"),
                    "agent_id": base_request.get("agent_id"),
                    "execution_id": base_request.get("execution_id"),
                    "policy_id": base_request.get("policy_id"),
                    "risk_score": gate.metadata.get("risk_score", 0),
                    "trust_score": base_request.get("trust_score"),
                    "allowed_tools": base_request.get("allowed_tools"),
                    "blocked_tools": base_request.get("blocked_tools"),
                    "tags": base_request.get("tags"),
                    "metadata": {
                        "source": "response_coordinator",
                        "incoming_verdict": gate.metadata.get("verdict"),
                    },
                },
            )
        else:
            session.merge_context(
                {
                    "risk_score": gate.metadata.get("risk_score"),
                    "allowed_tools": base_request.get("allowed_tools"),
                    "blocked_tools": base_request.get("blocked_tools"),
                    "tags": base_request.get("tags"),
                },
            )

        session.apply_supervisor_decision(supervisor.to_dict())

        coordinated = CoordinatedResponse(
            response_id=f"resp-{uuid4().hex}",
            request_id=request_id,
            session_id=session.session_id,
            outcome=self._derive_outcome(gate, supervisor, session),
            gate=gate.to_dict(),
            supervisor=supervisor.to_dict(),
            session=session.to_dict(),
            allow=self._is_allowed(supervisor, session),
            sandbox_required=self._sandbox_required(gate, supervisor),
            redaction_required=self._redaction_required(gate, supervisor),
            quarantine_required=self._quarantine_required(gate, supervisor, session),
            review_required=self._review_required(supervisor, session),
            review_id=supervisor.review_id,
            quarantine_id=session.quarantine_id,
            metadata={
                "gate_status": gate.status.value,
                "gate_action": gate.action.value,
                "supervisor_status": supervisor.status.value,
                "session_status": session.status.value,
            },
        )

        self._append_steps(coordinated, gate, supervisor, session)
        return coordinated

    def coordinate_dict(
        self,
        *,
        request: Mapping[str, Any],
        gate: GateDecision,
        supervisor: SupervisorDecision,
        session: RuntimeSession | None = None,
    ) -> dict[str, Any]:
        return self.coordinate(request=request, gate=gate, supervisor=supervisor, session=session).to_dict()

    def _derive_outcome(
        self,
        gate: GateDecision,
        supervisor: SupervisorDecision,
        session: RuntimeSession,
    ) -> ResponseOutcome:
        if supervisor.status in {SupervisorStatus.BLOCKED, SupervisorStatus.FAILED}:
            return ResponseOutcome.BLOCK
        if supervisor.status == SupervisorStatus.QUARANTINED or session.status == RuntimeSessionStatus.QUARANTINED:
            return ResponseOutcome.QUARANTINE
        if supervisor.status == SupervisorStatus.NEEDS_REVIEW or session.status == RuntimeSessionStatus.NEEDS_REVIEW:
            return ResponseOutcome.NEEDS_REVIEW

        if supervisor.status == SupervisorStatus.CONDITIONAL:
            if gate.action == RemediationAction.APPLY_REDACTION and gate.sandbox_required:
                return ResponseOutcome.ALLOW_WITH_CONTROLS
            if gate.action == RemediationAction.APPLY_REDACTION:
                return ResponseOutcome.ALLOW_WITH_REDACTION
            if gate.action == RemediationAction.SANDBOX_ONLY or gate.sandbox_required:
                return ResponseOutcome.ALLOW_WITH_SANDBOX
            return ResponseOutcome.ALLOW_WITH_CONTROLS

        if supervisor.status == SupervisorStatus.APPROVED and gate.status in {
            GateStatus.OPEN,
            GateStatus.CONDITIONAL,
        }:
            if gate.action == RemediationAction.SANDBOX_ONLY or gate.sandbox_required:
                return ResponseOutcome.ALLOW_WITH_SANDBOX
            if gate.action == RemediationAction.APPLY_REDACTION:
                return ResponseOutcome.ALLOW_WITH_REDACTION
            return ResponseOutcome.ALLOW

        if gate.status in {GateStatus.CLOSED, GateStatus.QUARANTINED}:
            if gate.action == RemediationAction.QUARANTINE:
                return ResponseOutcome.QUARANTINE
            if gate.action == RemediationAction.BLOCK:
                return ResponseOutcome.BLOCK

        if gate.status == GateStatus.NEEDS_REVIEW:
            return ResponseOutcome.NEEDS_REVIEW

        return ResponseOutcome.FAILED

    def _is_allowed(self, supervisor: SupervisorDecision, session: RuntimeSession) -> bool:
        if supervisor.status in {
            SupervisorStatus.BLOCKED,
            SupervisorStatus.QUARANTINED,
            SupervisorStatus.NEEDS_REVIEW,
            SupervisorStatus.FAILED,
        }:
            return False
        if session.status in {
            RuntimeSessionStatus.BLOCKED,
            RuntimeSessionStatus.QUARANTINED,
            RuntimeSessionStatus.NEEDS_REVIEW,
            RuntimeSessionStatus.FAILED,
        }:
            return False
        return True

    def _sandbox_required(self, gate: GateDecision, supervisor: SupervisorDecision) -> bool:
        if gate.sandbox_required:
            return True
        return bool(supervisor.metadata.get("sandbox_required") or supervisor.metadata.get("sandbox_only"))

    def _redaction_required(self, gate: GateDecision, supervisor: SupervisorDecision) -> bool:
        if gate.redaction_required:
            return True
        return bool(supervisor.metadata.get("redaction_required"))

    def _quarantine_required(
        self,
        gate: GateDecision,
        supervisor: SupervisorDecision,
        session: RuntimeSession,
    ) -> bool:
        if gate.quarantine_required or gate.action == RemediationAction.QUARANTINE:
            return True
        if supervisor.status == SupervisorStatus.QUARANTINED:
            return True
        if session.status == RuntimeSessionStatus.QUARANTINED:
            return True
        return False

    def _review_required(self, supervisor: SupervisorDecision, session: RuntimeSession) -> bool:
        if supervisor.status == SupervisorStatus.NEEDS_REVIEW:
            return True
        if session.status == RuntimeSessionStatus.NEEDS_REVIEW:
            return True
        return False

    def _append_steps(
        self,
        response: CoordinatedResponse,
        gate: GateDecision,
        supervisor: SupervisorDecision,
        session: RuntimeSession,
    ) -> None:
        response.add_step(
            kind="gate",
            status=gate.status.value,
            message=f"Gate evaluated with action={gate.action.value}.",
            metadata={
                "allowed": gate.allowed,
                "review_required": gate.review_required,
                "quarantine_required": gate.quarantine_required,
                "sandbox_required": gate.sandbox_required,
                "redaction_required": gate.redaction_required,
                "reasons": list(gate.reasons),
            },
        )

        response.add_step(
            kind="supervisor",
            status=supervisor.status.value,
            message=f"Supervisor resolved action={supervisor.action}.",
            metadata={
                "allowed": supervisor.allowed,
                "review_id": supervisor.review_id,
                "quarantine_required": supervisor.quarantine_required,
                "sandbox_required": supervisor.sandbox_required,
                "redaction_required": supervisor.redaction_required,
            },
        )

        response.add_step(
            kind="session",
            status=session.status.value,
            message="Runtime session updated.",
            metadata={
                "session_id": session.session_id,
                "review_id": session.review_id,
                "quarantine_id": session.quarantine_id,
                "risk_score": session.risk_score,
                "trust_score": session.trust_score,
            },
        )


def coordinate_response(
    *,
    request: Mapping[str, Any],
    gate: GateDecision,
    supervisor: SupervisorDecision,
    session: RuntimeSession | None = None,
) -> CoordinatedResponse:
    return ResponseCoordinator().coordinate(request=request, gate=gate, supervisor=supervisor, session=session)


def coordinate_response_dict(
    *,
    request: Mapping[str, Any],
    gate: GateDecision,
    supervisor: SupervisorDecision,
    session: RuntimeSession | None = None,
) -> dict[str, Any]:
    return coordinate_response(request=request, gate=gate, supervisor=supervisor, session=session).to_dict()


__all__ = [
    "CoordinatedResponse",
    "ResponseCoordinator",
    "ResponseOutcome",
    "ResponseStep",
    "coordinate_response",
    "coordinate_response_dict",
]
