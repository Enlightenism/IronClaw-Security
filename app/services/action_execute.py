from __future__ import annotations

from typing import TypedDict

from app.services.action_decision import evaluate_action_execution
from app.services.action_guard import ActionType
from app.services.verdict_enforcer import EnforcedVerdict


class ActionExecuteResult(TypedDict):
    action_type: ActionType
    target: str
    content: str
    policy_mode: str | None
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
    # Groq telemetry — propagated from EnforcedVerdict to callers and review records
    groq_verdict: str | None
    groq_risk_score: int | None
    groq_confidence: float | None
    groq_latency_ms: float | None
    groq_model_name: str | None
    groq_signals: list[str]
    groq_summary: str | None
    groq_decided_at: str | None
    enforced_at: str


def execute_guarded_action(
    action_type: ActionType,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
) -> ActionExecuteResult:
    decision: EnforcedVerdict = evaluate_action_execution(
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
        "groq_verdict": decision["groq_verdict"],
        "groq_risk_score": decision["groq_risk_score"],
        "groq_confidence": decision["groq_confidence"],
        "groq_latency_ms": decision["groq_latency_ms"],
        "groq_model_name": decision["groq_model_name"],
        "groq_signals": decision["groq_signals"],
        "groq_summary": decision["groq_summary"],
        "groq_decided_at": decision["groq_decided_at"],
        "enforced_at": decision["enforced_at"],
    }
