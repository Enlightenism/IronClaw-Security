from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from orchestrator.remediationgate import (
    GateDecision,
    RemediationAction,
    RemediationGate,
)
from orchestrator.reviewqueue import ReviewPriority, ReviewQueue


class SupervisorStatus(StrEnum):
    READY = "ready"
    APPROVED = "approved"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    NEEDS_REVIEW = "needs_review"
    CONDITIONAL = "conditional"
    FAILED = "failed"


@dataclass(slots=True)
class SupervisorEvent:
    event_id: str
    kind: str
    message: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "kind": self.kind,
            "message": self.message,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class SupervisorDecision:
    supervisor_id: str
    request_id: str
    status: SupervisorStatus
    allowed: bool
    action: str
    gate: dict[str, Any]
    review_id: str | None = None
    quarantine_required: bool = False
    sandbox_required: bool = False
    redaction_required: bool = False
    events: list[SupervisorEvent] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def add_event(self, kind: str, message: str, metadata: Mapping[str, Any] | None = None) -> None:
        self.events.append(
            SupervisorEvent(
                event_id=f"evt-{uuid4().hex}",
                kind=kind,
                message=message,
                metadata=dict(metadata or {}),
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "supervisor_id": self.supervisor_id,
            "request_id": self.request_id,
            "status": self.status.value,
            "allowed": self.allowed,
            "action": self.action,
            "gate": dict(self.gate),
            "review_id": self.review_id,
            "quarantine_required": self.quarantine_required,
            "sandbox_required": self.sandbox_required,
            "redaction_required": self.redaction_required,
            "events": [event.to_dict() for event in self.events],
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


class Supervisor:
    def __init__(
        self,
        gate: RemediationGate | None = None,
        review_queue: ReviewQueue | None = None,
        *,
        sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.gate = gate or RemediationGate()
        self.review_queue = review_queue or ReviewQueue()
        self.sink = sink

    def supervise(self, payload: Mapping[str, Any] | None) -> SupervisorDecision:
        request = dict(payload or {})
        request_id = str(request.get("request_id") or f"req-{uuid4().hex}")

        gate_decision = self.gate.evaluate(request)
        gate_verdict = str(gate_decision.metadata.get("verdict", "allow")).strip().lower()
        blocked = not gate_decision.allowed or gate_decision.action != RemediationAction.NONE or gate_verdict != "allow" or gate_decision.review_required or gate_decision.quarantine_required
        gate_payload = gate_decision.to_dict()
        gate_payload["allowed"] = not blocked
        gate_payload["action"] = "block" if blocked else "allow"
        gate_metadata = dict(gate_payload.get("metadata") or {})
        gate_metadata["verdict"] = "block" if blocked else "allow"
        gate_payload["metadata"] = gate_metadata
        decision = SupervisorDecision(
            supervisor_id=f"sup-{uuid4().hex}",
            request_id=request_id,
            status=SupervisorStatus.READY,
            allowed=not blocked,
            action="block" if blocked else "allow",
            gate=gate_payload,
            quarantine_required=gate_decision.quarantine_required or gate_decision.action == RemediationAction.QUARANTINE,
            sandbox_required=gate_decision.sandbox_required,
            redaction_required=gate_decision.redaction_required,
            metadata={
                "risk_score": gate_decision.metadata.get("risk_score"),
                "verdict": "block" if blocked else "allow",
            },
        )
        decision.add_event(
            "gate_evaluated",
            "Remediation gate evaluated request.",
            {"gate_status": gate_decision.status.value, "action": decision.action},
        )

        self._apply_gate_outcome(decision, gate_decision, request)
        self._emit(decision)
        return decision

    def supervise_dict(self, payload: Mapping[str, Any] | None) -> dict[str, Any]:
        return self.supervise(payload).to_dict()

    def _apply_gate_outcome(
        self,
        decision: SupervisorDecision,
        gate_decision: GateDecision,
        request: Mapping[str, Any],
    ) -> None:
        gate_verdict = str(gate_decision.metadata.get("verdict", "allow")).strip().lower()
        blocked = not gate_decision.allowed or gate_decision.action != RemediationAction.NONE or gate_verdict != "allow" or gate_decision.review_required or gate_decision.quarantine_required
        if not blocked:
            decision.status = SupervisorStatus.APPROVED
            decision.allowed = True
            decision.action = "allow"
            decision.add_event(
                "approved",
                "Supervisor approved the request without additional intervention.",
                {"reasons": gate_decision.reasons},
            )
            return

        decision.status = SupervisorStatus.BLOCKED
        decision.allowed = False
        decision.action = "block"
        decision.quarantine_required = decision.quarantine_required or (gate_decision.action == RemediationAction.QUARANTINE)
        if gate_decision.action == RemediationAction.REQUIRE_REVIEW or gate_decision.review_required:
            review_item = self.review_queue.create(
                request_id=decision.request_id,
                execution_id=str(request.get("execution_id")) if request.get("execution_id") else None,
                title=str(request.get("title") or "Security review required"),
                summary=str(request.get("summary") or "Supervisor routed request into review queue."),
                priority=self._review_priority_from_request(request, gate_decision),
                queue=str(request.get("review_queue") or "security"),
                created_by=str(request.get("actor_id") or "supervisor"),
                due_in_minutes=int(request.get("review_due_in_minutes", 60) or 60),
                escalate_in_minutes=int(request.get("review_escalate_in_minutes", 30) or 30),
                tags=request.get("tags") or [],
                metadata={
                    "source": "supervisor",
                    "gate_action": "block",
                    "gate_status": gate_decision.status.value,
                },
            )
            decision.status = SupervisorStatus.NEEDS_REVIEW
            decision.allowed = False
            decision.review_id = review_item.review_id
            decision.add_event(
                "review_created",
                "Supervisor created a human review item.",
                {"review_id": review_item.review_id, "queue": review_item.queue},
            )
        if decision.quarantine_required:
            decision.add_event(
                "quarantined",
                "Containment is required while the request remains blocked.",
                {"verdict": "block"},
            )
        decision.add_event(
            "blocked",
            "Supervisor blocked the request.",
            {
                "reasons": gate_decision.reasons,
                "quarantine_required": decision.quarantine_required,
            },
        )

    def _review_priority_from_request(
        self,
        request: Mapping[str, Any],
        gate_decision: GateDecision,
    ) -> ReviewPriority:
        explicit = request.get("review_priority")
        if explicit:
            return ReviewPriority(str(explicit).lower())

        try:
            risk_score = int(gate_decision.metadata.get("risk_score", 0) or 0)
        except (TypeError, ValueError, OverflowError):
            risk_score = RISK_THRESHOLD_BLOCK_MIN
        if gate_decision.quarantine_required:
            return ReviewPriority.CRITICAL
        if risk_score >= RISK_THRESHOLD_BLOCK_MIN:
            return ReviewPriority.HIGH
        if risk_score > RISK_THRESHOLD_ALLOW_MAX:
            return ReviewPriority.MEDIUM
        return ReviewPriority.LOW

    def _emit(self, decision: SupervisorDecision) -> None:
        if self.sink is not None:
            self.sink(
                {
                    "event": "supervisor.decision",
                    "decision": decision.to_dict(),
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            )


def supervise_request(payload: Mapping[str, Any] | None) -> SupervisorDecision:
    return Supervisor().supervise(payload)


def supervise_request_dict(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    return supervise_request(payload).to_dict()


__all__ = [
    "Supervisor",
    "SupervisorDecision",
    "SupervisorEvent",
    "SupervisorStatus",
    "supervise_request",
    "supervise_request_dict",
]
