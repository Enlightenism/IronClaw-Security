from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ExecutionState = Literal["executed", "denied", "held", "failed"]
ResponseAction = Literal["allow", "warn", "quarantine", "block", "review"]
ResponseStatus = Literal["completed", "queued_for_review", "denied"]
PolicyVerdict = Literal["allow", "warn", "quarantine", "block"]
ReasonSource = Literal["policy", "scan", "ai"]


class ExecuteReason(BaseModel):
    source: ReasonSource
    label: str
    details: str
    score: float | None = None


class ExecuteRequest(BaseModel):
    action_type: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    content: str = Field(default="")
    risk_score: int = Field(ge=0, le=100)
    client_id: str | None = None
    session_id: str | None = None
    file_path: str | None = None


class ExecuteResponse(BaseModel):
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
    review_item_id: str | None = None
    executor_name: str | None = None
    executor_result: dict[str, Any] | None = None
    reason: str
    reasons: list[ExecuteReason] = Field(default_factory=list)
