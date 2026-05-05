from __future__ import annotations

from typing import TypedDict

from app.services.action_decision import (
    ActionExecutionDecision,
    evaluate_action_execution,
)
from app.services.action_guard import ActionType


class ActionExecuteResult(TypedDict):
    action_type: ActionType
    target: str
    content: str
    policy_mode: str
    verdict: str
    summary: str
    risk_score: int
    matched_patterns: list[str]
    scan_id: str | None
    should_halt: bool
    should_warn: bool
    decision_source: str
    client_id: str | None
    session_id: str | None
    executed: bool
    execution_status: str
    execution_message: str
    reasons: list[dict[str, object]]


def execute_guarded_action(
    action_type: ActionType,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
) -> ActionExecuteResult:
    decision: ActionExecutionDecision = evaluate_action_execution(
        action_type=action_type,
        target=target,
        content=content,
        client_id=client_id,
        session_id=session_id,
    )

    if decision["should_halt"]:
        execution_status = "halted"
        execution_message = "Action execution was halted by guard controls."
        executed = False
    elif decision["should_warn"]:
        execution_status = "review_required"
        execution_message = "Action requires review before execution."
        executed = False
    else:
        execution_status = "allowed"
        execution_message = "Action passed guard checks and is eligible for execution."
        executed = True

    return {
        "action_type": decision["action_type"],
        "target": decision["target"],
        "content": decision["content"],
        "policy_mode": decision["policy_mode"],
        "verdict": decision["verdict"],
        "summary": decision["summary"],
        "risk_score": decision["risk_score"],
        "matched_patterns": decision["matched_patterns"],
        "scan_id": decision["scan_id"],
        "should_halt": decision["should_halt"],
        "should_warn": decision["should_warn"],
        "decision_source": decision["decision_source"],
        "client_id": decision["client_id"],
        "session_id": decision["session_id"],
        "executed": executed,
        "execution_status": execution_status,
        "execution_message": execution_message,
        "reasons": decision["reasons"],
    }