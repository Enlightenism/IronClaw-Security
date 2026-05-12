from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.orchestrator.execution_plan import ExecutionPlan
from app.orchestrator.replay_controller import ReplayReport
from app.orchestrator.supervisor import SupervisorEscalation

ReviewAction = str
GateStatus = str
RemediationDecision = str


@dataclass(frozen=True)
class GateReviewRequest:
    request_id: str
    source: str
    target: str
    verdict: str
    risk_score: int
    reason: str
    requested_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GateReviewOutcome:
    outcome_id: str
    request_id: str
    status: GateStatus
    decision: RemediationDecision
    action: ReviewAction
    rationale: str
    reviewed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RemediationGateReport:
    gate_id: str
    created_at: str
    request_count: int
    approved_count: int
    rejected_count: int
    quarantined_count: int
    manual_review_count: int
    outcomes: list[GateReviewOutcome] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "created_at": self.created_at,
            "request_count": self.request_count,
            "approved_count": self.approved_count,
            "rejected_count": self.rejected_count,
            "quarantined_count": self.quarantined_count,
            "manual_review_count": self.manual_review_count,
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


def build_request_from_execution_plan(
    plan: ExecutionPlan,
    *,
    target: str,
    source: str = "execution-plan",
) -> GateReviewRequest:
    reason = f"Execution plan verdict={plan.verdict} with risk_score={plan.risk_score}."
    return GateReviewRequest(
        request_id=f"req-{uuid4().hex[:12]}",
        source=source,
        target=target,
        verdict=plan.verdict,
        risk_score=plan.risk_score,
        reason=reason,
    )


def build_requests_from_replay(report: ReplayReport) -> list[GateReviewRequest]:
    requests: list[GateReviewRequest] = []
    for step in report.steps:
        requests.append(
            GateReviewRequest(
                request_id=f"req-{uuid4().hex[:12]}",
                source=f"replay:{report.replay_id}",
                target=step.target,
                verdict=step.verdict,
                risk_score=step.risk_score,
                reason=f"Replay outcome={step.replay_outcome} for trace={step.trace_id}.",
            )
        )
    return requests


def build_requests_from_escalations(
    escalations: list[SupervisorEscalation],
) -> list[GateReviewRequest]:
    requests: list[GateReviewRequest] = []
    for escalation in escalations:
        requests.append(
            GateReviewRequest(
                request_id=f"req-{uuid4().hex[:12]}",
                source=f"escalation:{escalation.escalation_id}",
                target=escalation.file_path,
                verdict=escalation.verdict,
                risk_score=escalation.risk_score,
                reason=escalation.reason,
            )
        )
    return requests


def _decision_for_request(request: GateReviewRequest) -> tuple[GateStatus, RemediationDecision, ReviewAction, str]:
    if request.verdict == "block":
        return (
            "closed",
            "reject",
            "deny",
            "Blocked verdict requires denial and remediation before any further execution.",
        )

    if request.verdict == "quarantine":
        return (
            "contained",
            "isolate",
            "sandbox-review",
            "Quarantined verdict requires isolated handling and explicit sandbox review.",
        )

    if request.verdict == "warn" or request.risk_score >= 70:
        return (
            "pending-review",
            "review",
            "manual-review",
            "Elevated risk requires explicit human or higher-policy approval.",
        )

    return (
        "approved",
        "approve",
        "allow",
        "Low-risk request can proceed under current remediation policy.",
    )


def review_requests(requests: list[GateReviewRequest]) -> RemediationGateReport:
    outcomes: list[GateReviewOutcome] = []

    for request in requests:
        status, decision, action, rationale = _decision_for_request(request)
        outcomes.append(
            GateReviewOutcome(
                outcome_id=f"out-{uuid4().hex[:12]}",
                request_id=request.request_id,
                status=status,
                decision=decision,
                action=action,
                rationale=rationale,
            )
        )

    approved_count = sum(1 for item in outcomes if item.decision == "approve")
    rejected_count = sum(1 for item in outcomes if item.decision == "reject")
    quarantined_count = sum(1 for item in outcomes if item.decision == "isolate")
    manual_review_count = sum(1 for item in outcomes if item.decision == "review")

    return RemediationGateReport(
        gate_id=f"gate-{uuid4().hex[:16]}",
        created_at=datetime.now(UTC).isoformat(),
        request_count=len(requests),
        approved_count=approved_count,
        rejected_count=rejected_count,
        quarantined_count=quarantined_count,
        manual_review_count=manual_review_count,
        outcomes=outcomes,
    )


def summarize_gate_report(report: RemediationGateReport) -> dict[str, Any]:
    return {
        "gate_id": report.gate_id,
        "request_count": report.request_count,
        "approved_count": report.approved_count,
        "rejected_count": report.rejected_count,
        "quarantined_count": report.quarantined_count,
        "manual_review_count": report.manual_review_count,
    }


if __name__ == "__main__":
    import json

    sample_requests = [
        GateReviewRequest(
            request_id="req-allow",
            source="demo",
            target="app/services/health.py",
            verdict="allow",
            risk_score=0,
            reason="Health-check action.",
        ),
        GateReviewRequest(
            request_id="req-warn",
            source="demo",
            target="app/orchestrator/router.py",
            verdict="warn",
            risk_score=75,
            reason="Elevated routing change.",
        ),
        GateReviewRequest(
            request_id="req-quarantine",
            source="demo",
            target="suspicious-bundle.zip",
            verdict="quarantine",
            risk_score=70,
            reason="Archive requires sandbox review.",
        ),
        GateReviewRequest(
            request_id="req-block",
            source="demo",
            target="app/secrets/export.py",
            verdict="block",
            risk_score=100,
            reason="Credential exposure attempt.",
        ),
    ]

    report = review_requests(sample_requests)
    print(json.dumps({"summary": summarize_gate_report(report), "report": report.to_dict()}, ensure_ascii=False, indent=2))