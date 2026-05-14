from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.orchestrator.review_state_store import (
    ExecutionReceipt,
    ReviewStateSnapshot,
    ReviewStateStore,
    initialize_review_state_store,
)


@dataclass(frozen=True)
class ExecutionRequest:
    review_item_id: str
    action_type: str
    target: str
    requested_by: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionResult:
    review_item_id: str
    final_status: str
    message: str
    receipt: ExecutionReceipt
    output_ref: str | None = None
    executor_response: dict[str, Any] = field(default_factory=dict)


class ExecutorBoundary:
    def __init__(
        self,
        *,
        store: ReviewStateStore,
        executors: dict[str, Callable[[ExecutionRequest, ReviewStateSnapshot], dict[str, Any]]],
    ) -> None:
        self.store = store
        self.executors = executors

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        snapshot = self.store.get_snapshot(request.review_item_id)
        item = snapshot.item

        if item.status == "pending":
            receipt = self.store.add_execution_receipt(
                review_item_id=request.review_item_id,
                action_type=request.action_type,
                target=request.target,
                executed_by=request.requested_by,
                status="blocked",
                blocked_reason="review pending; execution denied until decision is recorded",
                metadata={"gate": "review_status"},
            )
            return ExecutionResult(
                review_item_id=request.review_item_id,
                final_status="blocked",
                message="Execution blocked because the review item is still pending.",
                receipt=receipt,
            )

        if item.status == "rejected":
            receipt = self.store.add_execution_receipt(
                review_item_id=request.review_item_id,
                action_type=request.action_type,
                target=request.target,
                executed_by=request.requested_by,
                status="blocked",
                blocked_reason="review rejected; execution permanently denied",
                metadata={"gate": "review_status"},
            )
            return ExecutionResult(
                review_item_id=request.review_item_id,
                final_status="blocked",
                message="Execution blocked because the review item was rejected.",
                receipt=receipt,
            )

        executor = self.executors.get(request.action_type)
        if executor is None:
            receipt = self.store.add_execution_receipt(
                review_item_id=request.review_item_id,
                action_type=request.action_type,
                target=request.target,
                executed_by=request.requested_by,
                status="blocked",
                blocked_reason=f"no executor registered for action_type={request.action_type}",
                metadata={"gate": "executor_registry"},
            )
            return ExecutionResult(
                review_item_id=request.review_item_id,
                final_status="blocked",
                message=f"No executor is registered for action type '{request.action_type}'.",
                receipt=receipt,
            )

        executor_response = executor(request, snapshot)
        normalized_status = _normalize_executor_status(executor_response.get("status"))
        output_ref = executor_response.get("output_ref")
        blocked_reason = executor_response.get("blocked_reason")

        receipt = self.store.add_execution_receipt(
            review_item_id=request.review_item_id,
            action_type=request.action_type,
            target=request.target,
            executed_by=request.requested_by,
            status=normalized_status,
            output_ref=output_ref,
            blocked_reason=blocked_reason,
            metadata={
                "gate": "executor_run",
                **request.metadata,
                **executor_response.get("metadata", {}),
            },
        )

        message = _build_message(normalized_status, request.action_type, request.target)
        return ExecutionResult(
            review_item_id=request.review_item_id,
            final_status=normalized_status,
            message=message,
            receipt=receipt,
            output_ref=output_ref,
            executor_response=executor_response,
        )


def initialize_executor_boundary(
    *,
    store_path: str = "output/review-state-store.jsonl",
) -> ExecutorBoundary:
    store = initialize_review_state_store(store_path)
    return ExecutorBoundary(
        store=store,
        executors={
            "sandbox_fetch": sandbox_fetch_executor,
            "sandbox_scan": sandbox_scan_executor,
            "sandbox_render": sandbox_render_executor,
        },
    )


def sandbox_fetch_executor(
    request: ExecutionRequest,
    snapshot: ReviewStateSnapshot,
) -> dict[str, Any]:
    output_ref = f"sandbox://fetch/{request.review_item_id}"
    return {
        "status": "executed",
        "output_ref": output_ref,
        "metadata": {
            "approved_status": snapshot.item.status,
            "target_type": snapshot.item.target_type,
        },
    }


def sandbox_scan_executor(
    request: ExecutionRequest,
    snapshot: ReviewStateSnapshot,
) -> dict[str, Any]:
    output_ref = f"sandbox://scan/{request.review_item_id}"
    return {
        "status": "executed",
        "output_ref": output_ref,
        "metadata": {
            "approved_status": snapshot.item.status,
            "risk_score": snapshot.item.risk_score,
        },
    }


def sandbox_render_executor(
    request: ExecutionRequest,
    snapshot: ReviewStateSnapshot,
) -> dict[str, Any]:
    if snapshot.item.target_type not in {"githubrepo", "archive", "text"}:
        return {
            "status": "blocked",
            "blocked_reason": f"unsupported target_type={snapshot.item.target_type}",
            "metadata": {"approved_status": snapshot.item.status},
        }

    return {
        "status": "executed",
        "output_ref": f"sandbox://render/{request.review_item_id}",
        "metadata": {
            "approved_status": snapshot.item.status,
            "target_type": snapshot.item.target_type,
        },
    }


def summarize_execution_result(result: ExecutionResult) -> dict[str, Any]:
    return {
        "review_item_id": result.review_item_id,
        "final_status": result.final_status,
        "message": result.message,
        "receipt_id": result.receipt.receipt_id,
        "receipt_status": result.receipt.status,
        "output_ref": result.output_ref,
    }


def _normalize_executor_status(value: Any) -> str:
    allowed = {"executed", "blocked", "expired"}
    if value in allowed:
        return value
    return "blocked"


def _build_message(status: str, action_type: str, target: str) -> str:
    if status == "executed":
        return f"Execution completed for {action_type} on {target}."
    if status == "expired":
        return f"Execution window expired for {action_type} on {target}."
    return f"Execution was blocked for {action_type} on {target}."


if __name__ == "__main__":
    import json

    store = initialize_review_state_store("output/review-state-store.jsonl")

    created = store.create_item(
        review_item_id="review-0002",
        scan_id="scan-def456",
        actor_id="agent-security-02",
        target_type="githubrepo",
        target_value="https://github.com/example/approved-repo",
        risk_score=70,
        reason="githubrepo requires sandbox review",
        metadata={"source": "executor_demo"},
    )

    store.set_decision(
        review_item_id=created.review_item_id,
        decision="approved",
        decided_by="reviewer-ops-02",
        notes="Safe to run in sandbox only",
    )

    boundary = ExecutorBoundary(
        store=store,
        executors={"sandbox_fetch": sandbox_fetch_executor},
    )

    result = boundary.execute(
        ExecutionRequest(
            review_item_id="review-0002",
            action_type="sandbox_fetch",
            target="https://github.com/example/approved-repo",
            requested_by="runtime-executor-01",
            metadata={"trigger": "manual_test"},
        ),
    )

    print(json.dumps(summarize_execution_result(result), ensure_ascii=False, indent=2))
