from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.runtime.networkguard import NetworkGuard, build_network_guard
from app.services.action_guard import normalize_action_type

PolicyVerdict = Literal["allow", "block"]


def _is_valid_risk_score(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100


@dataclass
class BoundaryRequest:
    actor_id: str | None
    action_type: str
    target: str
    content: str
    risk_score: int
    session_id: str | None
    file_path: str
    metadata: dict[str, Any]


@dataclass
class BoundaryDecision:
    decision_id: str
    verdict: PolicyVerdict
    reasons: list[str]
    review_item_id: str | None = None


@dataclass
class BoundaryRuntimeResult:
    request_id: str
    trace_id: str
    decision: BoundaryDecision


@dataclass
class ExecutionReceipt:
    execution_id: str
    state: str
    response_action: str
    response_status: str
    trace_id: str
    request_id: str
    decision_id: str
    policy_verdict: PolicyVerdict
    risk_score: int
    should_execute: bool
    halted_by_boundary: bool
    review_item_id: str | None
    executor_name: str | None
    executor_result: dict[str, Any] | None
    reason: str
    reasons: list[str]


@lru_cache(maxsize=1)
def _get_network_guard() -> NetworkGuard:
    return build_network_guard()


def _build_runtime_result(
    *,
    risk_score: int,
    network_policy_blocked: bool = False,
) -> BoundaryRuntimeResult:
    if network_policy_blocked:
        verdict = "block"
        reasons = ["Request blocked by the configured network egress policy."]
        review_item_id = "review-001"
    elif risk_score > RISK_THRESHOLD_ALLOW_MAX:
        verdict = "block"
        reasons = ["Request blocked by the configured executor-boundary risk policy."]
        review_item_id = "review-001"
    else:
        verdict = "allow"
        reasons = ["Request allowed by executor boundary."]
        review_item_id = None

    decision = BoundaryDecision(
        decision_id="decision-001",
        verdict=verdict,
        reasons=reasons,
        review_item_id=review_item_id,
    )
    return BoundaryRuntimeResult(
        request_id="request-001",
        trace_id="trace-001",
        decision=decision,
    )


def dry_run_executor(request: BoundaryRequest) -> dict[str, Any]:
    return {
        "mode": "dry_run",
        "target": request.target,
        "action_type": request.action_type,
        "actor_id": request.actor_id or "",
        "session_id": request.session_id,
        "file_path": request.file_path,
    }


def execute_with_boundary(
    *,
    pipeline: Any,
    actor_id: str | None,
    action_type: str,
    target: str,
    content: str,
    risk_score: int,
    session_id: str | None,
    file_path: str,
    metadata: dict[str, Any] | None = None,
    executor: Callable[[BoundaryRequest], dict[str, Any]] | None = None,
) -> tuple[ExecutionReceipt, BoundaryRuntimeResult]:
    risk_score_is_valid = _is_valid_risk_score(risk_score)
    risk_score = max(0, min(100, risk_score)) if risk_score_is_valid else RISK_THRESHOLD_BLOCK_MIN
    if risk_score > RISK_THRESHOLD_ALLOW_MAX:
        risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)
    network_policy_blocked = normalize_action_type(action_type) == "network_request" and not _get_network_guard().allow(url=target, metadata={"direction": "egress"})
    if network_policy_blocked:
        risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)

    request = BoundaryRequest(
        actor_id=actor_id,
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        session_id=session_id,
        file_path=file_path,
        metadata=metadata or {},
    )

    runtime_result = _build_runtime_result(
        risk_score=risk_score,
        network_policy_blocked=network_policy_blocked,
    )
    decision = runtime_result.decision
    if not risk_score_is_valid:
        decision.reasons.insert(0, "Invalid risk score; request blocked by executor boundary.")

    if decision.verdict == "block":
        receipt = ExecutionReceipt(
            execution_id="exec-001",
            state="denied",
            response_action=decision.verdict,
            response_status="denied",
            trace_id=runtime_result.trace_id,
            request_id=runtime_result.request_id,
            decision_id=decision.decision_id,
            policy_verdict=decision.verdict,
            risk_score=risk_score,
            should_execute=False,
            halted_by_boundary=True,
            review_item_id=decision.review_item_id,
            executor_name=None,
            executor_result=None,
            reason=decision.reasons[0],
            reasons=decision.reasons,
        )
        return receipt, runtime_result

    active_executor = executor or dry_run_executor
    executor_name = getattr(active_executor, "__name__", "executor")

    try:
        executor_result = active_executor(request)
        if not isinstance(executor_result, dict):
            raise TypeError("Executor must return a dict result.")
    except Exception as exc:
        receipt = ExecutionReceipt(
            execution_id="exec-001",
            state="failed",
            response_action="review",
            response_status="queued_for_review",
            trace_id=runtime_result.trace_id,
            request_id=runtime_result.request_id,
            decision_id=decision.decision_id,
            policy_verdict=decision.verdict,
            risk_score=risk_score,
            should_execute=False,
            halted_by_boundary=False,
            review_item_id=decision.review_item_id,
            executor_name=executor_name,
            executor_result=None,
            reason=f"Executor failed: {exc}",
            reasons=[f"Executor failed: {exc}"],
        )
        return receipt, runtime_result

    receipt = ExecutionReceipt(
        execution_id="exec-001",
        state="executed",
        response_action="allow",
        response_status="completed",
        trace_id=runtime_result.trace_id,
        request_id=runtime_result.request_id,
        decision_id=decision.decision_id,
        policy_verdict=decision.verdict,
        risk_score=risk_score,
        should_execute=True,
        halted_by_boundary=False,
        review_item_id=decision.review_item_id,
        executor_name=executor_name,
        executor_result=executor_result,
        reason="Execution completed successfully.",
        reasons=decision.reasons,
    )
    return receipt, runtime_result


def summarize_execution_receipt(
    receipt: ExecutionReceipt,
    runtime_result: BoundaryRuntimeResult,
) -> dict[str, Any]:
    return {
        "execution_id": receipt.execution_id,
        "execution_state": receipt.state,
        "response_action": receipt.response_action,
        "response_status": receipt.response_status,
        "trace_id": receipt.trace_id,
        "request_id": receipt.request_id,
        "decision_id": receipt.decision_id,
        "policy_verdict": receipt.policy_verdict,
        "risk_score": receipt.risk_score,
        "should_execute": receipt.should_execute,
        "halted_by_boundary": receipt.halted_by_boundary,
        "review_item_id": receipt.review_item_id,
        "executor_name": receipt.executor_name,
        "executor_result": receipt.executor_result,
        "reason": receipt.reason,
        "reasons": receipt.reasons,
    }
