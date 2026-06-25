from __future__ import annotations

from typing import Any, Literal

from typing_extensions import TypedDict

ExecutionState = Literal["executed", "denied", "held", "failed"]
ResponseAction = Literal["allow", "warn", "quarantine", "block", "review"]
ResponseStatus = Literal["completed", "queued_for_review", "denied"]
PolicyVerdict = Literal["allow", "warn", "quarantine", "block"]
ReasonSource = Literal["policy", "scan", "ai"]


class ExecutionReason(TypedDict):
    source: ReasonSource
    label: str
    details: str
    score: float | None


class ExecutorResult(TypedDict, total=False):
    mode: str
    message: str
    target: str
    action_type: str
    actor_id: str
    session_id: str | None
    file_path: str | None
    executed_target: str
    executed_action_type: str
    matched_patterns: list[str]
    details: dict[str, Any]


class ActionExecuteResult(TypedDict):
    execution_id: str
    execution_state: ExecutionState
    response_action: ResponseAction
    response_status: ResponseStatus
    trace_id: str
    request_id: str
    decision_id: str
    policy_verdict: PolicyVerdict
    risk_score: int
    should_execute: bool
    halted_by_boundary: bool
    review_item_id: str | None
    executor_name: str | None
    executor_result: ExecutorResult | None
    reason: str
    reasons: list[ExecutionReason]
    file_path: str | None
