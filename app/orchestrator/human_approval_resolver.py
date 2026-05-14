from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.orchestrator.executor_boundary import ExecutionReceipt
from app.orchestrator.secure_runtime_pipeline import RuntimeRequest

ReviewDecision = Literal["approved", "rejected", "pending"]
ResolutionOutcome = Literal["execute", "deny", "hold"]


@dataclass(frozen=True)
class ApprovalRecord:
    review_item_id: str
    decision: ReviewDecision
    reviewer_id: str
    reason: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalResolution:
    resolution_id: str
    review_item_id: str
    outcome: ResolutionOutcome
    final_state: str
    reason: str
    approval: ApprovalRecord
    execution_receipt: ExecutionReceipt | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolution_id": self.resolution_id,
            "review_item_id": self.review_item_id,
            "outcome": self.outcome,
            "final_state": self.final_state,
            "reason": self.reason,
            "approval": self.approval.to_dict(),
            "execution_receipt": (self.execution_receipt.to_dict() if self.execution_receipt else None),
            "created_at": self.created_at,
        }


class HumanApprovalResolverError(RuntimeError):
    pass


def create_approval_record(
    *,
    review_item_id: str,
    decision: ReviewDecision,
    reviewer_id: str,
    reason: str,
    metadata: dict[str, Any] | None = None,
) -> ApprovalRecord:
    normalized_decision = decision.strip().lower()
    if normalized_decision not in {"approved", "rejected", "pending"}:
        raise HumanApprovalResolverError(
            "decision must be one of: approved, rejected, pending",
        )

    return ApprovalRecord(
        review_item_id=review_item_id,
        decision=normalized_decision,  # type: ignore[arg-type]
        reviewer_id=reviewer_id,
        reason=reason,
        metadata=metadata or {},
    )


def resolve_human_approval(
    *,
    approval: ApprovalRecord,
    request: RuntimeRequest,
    executor: Callable[[RuntimeRequest], dict[str, Any]] | None = None,
    prior_receipt: ExecutionReceipt | None = None,
) -> ApprovalResolution:
    if approval.decision == "pending":
        return ApprovalResolution(
            resolution_id=_build_resolution_id(),
            review_item_id=approval.review_item_id,
            outcome="hold",
            final_state="held",
            reason=approval.reason,
            approval=approval,
            execution_receipt=prior_receipt,
        )

    if approval.decision == "rejected":
        denied_receipt = ExecutionReceipt(
            execution_id=_build_execution_id(),
            state="denied",
            action="review",
            status="completed",
            trace_id=prior_receipt.trace_id if prior_receipt else "manual-review",
            request_id=prior_receipt.request_id if prior_receipt else "manual-request",
            decision_id=prior_receipt.decision_id if prior_receipt else "manual-decision",
            reason=approval.reason,
            review_item_id=approval.review_item_id,
            executor_name=None,
            executor_result=None,
        )
        return ApprovalResolution(
            resolution_id=_build_resolution_id(),
            review_item_id=approval.review_item_id,
            outcome="deny",
            final_state="denied",
            reason=approval.reason,
            approval=approval,
            execution_receipt=denied_receipt,
        )

    executed_receipt = _execute_after_approval(
        request=request,
        approval=approval,
        prior_receipt=prior_receipt,
        executor=executor,
    )
    return ApprovalResolution(
        resolution_id=_build_resolution_id(),
        review_item_id=approval.review_item_id,
        outcome="execute",
        final_state=executed_receipt.state,
        reason=approval.reason,
        approval=approval,
        execution_receipt=executed_receipt,
    )


def summarize_approval_resolution(resolution: ApprovalResolution) -> dict[str, Any]:
    return {
        "resolution_id": resolution.resolution_id,
        "review_item_id": resolution.review_item_id,
        "decision": resolution.approval.decision,
        "reviewer_id": resolution.approval.reviewer_id,
        "outcome": resolution.outcome,
        "final_state": resolution.final_state,
        "reason": resolution.reason,
        "execution_id": (resolution.execution_receipt.execution_id if resolution.execution_receipt else None),
        "execution_state": (resolution.execution_receipt.state if resolution.execution_receipt else None),
    }


def _execute_after_approval(
    *,
    request: RuntimeRequest,
    approval: ApprovalRecord,
    prior_receipt: ExecutionReceipt | None,
    executor: Callable[[RuntimeRequest], dict[str, Any]] | None,
) -> ExecutionReceipt:
    try:
        if executor is None:
            executor_result = {
                "mode": "dry_run_after_approval",
                "message": "Approved review item is ready for execution.",
                "target": request.target,
                "action_type": request.action_type,
                "review_item_id": approval.review_item_id,
            }
            executor_name = "dry_run_executor"
        else:
            executor_result = executor(request)
            if not isinstance(executor_result, dict):
                raise HumanApprovalResolverError("Executor must return a dict result.")
            executor_name = getattr(executor, "__name__", executor.__class__.__name__)
    except Exception as exc:  # noqa: BLE001
        return ExecutionReceipt(
            execution_id=_build_execution_id(),
            state="failed",
            action="review",
            status="completed",
            trace_id=prior_receipt.trace_id if prior_receipt else "manual-review",
            request_id=prior_receipt.request_id if prior_receipt else "manual-request",
            decision_id=prior_receipt.decision_id if prior_receipt else "manual-decision",
            reason=f"Approved execution failed: {exc}",
            review_item_id=approval.review_item_id,
            executor_name=getattr(executor, "__name__", "dry_run_executor") if executor else "dry_run_executor",
            executor_result=None,
        )

    return ExecutionReceipt(
        execution_id=_build_execution_id(),
        state="executed",
        action="review",
        status="completed",
        trace_id=prior_receipt.trace_id if prior_receipt else "manual-review",
        request_id=prior_receipt.request_id if prior_receipt else "manual-request",
        decision_id=prior_receipt.decision_id if prior_receipt else "manual-decision",
        reason=approval.reason,
        review_item_id=approval.review_item_id,
        executor_name=executor_name,
        executor_result=executor_result,
    )


def _build_resolution_id() -> str:
    now = datetime.now(UTC)
    return f"resolve-{now.strftime('%Y%m%d%H%M%S%f')}"


def _build_execution_id() -> str:
    now = datetime.now(UTC)
    return f"exec-{now.strftime('%Y%m%d%H%M%S%f')}"


if __name__ == "__main__":
    import json

    def demo_executor(request: RuntimeRequest) -> dict[str, Any]:
        return {
            "mode": "simulated",
            "actor_id": request.actor_id,
            "target": request.target,
            "action_type": request.action_type,
        }

    request = RuntimeRequest(
        actor_id="agent-security-01",
        action_type="repo_ingest",
        target="https://github.com/example/approve-repo",
        content="Clone repository in a sandbox after review approval.",
        risk_score=70,
        session_id="sess-review-001",
        file_path="app/orchestrator/human_approval_resolver.py",
        metadata={"source": "human_approval_demo"},
    )

    prior_receipt = ExecutionReceipt(
        execution_id="exec-held-001",
        state="held",
        action="review",
        status="queued_for_review",
        trace_id="trace-held-001",
        request_id="req-held-001",
        decision_id="dec-held-001",
        reason="Repository requires sandbox review before execution.",
        review_item_id="review-001",
    )

    approved = create_approval_record(
        review_item_id="review-001",
        decision="approved",
        reviewer_id="analyst-01",
        reason="Repository approved for sandbox execution.",
    )

    rejected = create_approval_record(
        review_item_id="review-002",
        decision="rejected",
        reviewer_id="analyst-02",
        reason="Archive rejected due to trust concerns.",
    )

    approved_resolution = resolve_human_approval(
        approval=approved,
        request=request,
        executor=demo_executor,
        prior_receipt=prior_receipt,
    )

    rejected_resolution = resolve_human_approval(
        approval=rejected,
        request=request,
        executor=demo_executor,
        prior_receipt=prior_receipt,
    )

    print(
        json.dumps(
            {
                "approved": summarize_approval_resolution(approved_resolution),
                "rejected": summarize_approval_resolution(rejected_resolution),
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
