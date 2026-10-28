from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.core.auth import require_api_key
from app.orchestrator.policy_enforcer import enforce_policy, initialize_policy_engine
from app.services.action_decision import evaluate_action_execution

router = APIRouter(prefix="/guard", tags=["guard"])

_ENGINE = initialize_policy_engine(mode="enforce")


def build_trace_id() -> str:
    return f"trace-{uuid4().hex[:16]}"


class ActionDecisionRequest(BaseModel):
    action_type: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    content: str = ""
    client_id: str | None = None
    session_id: str | None = None
    file_path: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecuteRequest(BaseModel):
    action_type: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    content: str = ""
    risk_score: int = Field(default=0, ge=0, le=100)
    client_id: str | None = None
    session_id: str | None = None
    file_path: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


def _merge_metadata(payload_metadata: dict[str, Any], *, session_id: str | None) -> dict[str, Any]:
    merged = dict(payload_metadata or {})
    if session_id and "session_id" not in merged:
        merged["session_id"] = session_id
    return merged


@router.post("/action-decision", dependencies=[Depends(require_api_key)])
def action_decision(payload: ActionDecisionRequest, request: Request) -> dict[str, Any]:
    trace_id = build_trace_id()

    tool_decision = evaluate_action_execution(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        client_id=payload.client_id,
        session_id=payload.session_id,
    )

    return {
        "trace_id": trace_id,
        "verdict": tool_decision["verdict"],
        "risk_score": int(tool_decision["risk_score"]),
        "should_halt": bool(tool_decision["should_halt"]),
        "summary": tool_decision.get("summary", ""),
        "decision_source": tool_decision.get("decision_source", "unknown"),
        "matched_patterns": list(tool_decision.get("matched_patterns", [])),
    }


@router.post("/execute", dependencies=[Depends(require_api_key)])
def guarded_execute(payload: ExecuteRequest, request: Request) -> dict[str, Any]:
    trace_id = build_trace_id()

    policy_decision = enforce_policy(
        _ENGINE,
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        risk_score=payload.risk_score,
        agent_id=payload.client_id,
        file_path=payload.file_path,
        metadata=_merge_metadata(payload.metadata, session_id=payload.session_id),
    )

    verdict = "allow" if policy_decision.verdict == "allow" and policy_decision.allow_execution else "block"
    risk_score = int(policy_decision.risk_score)
    if verdict == "block":
        risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)

    if policy_decision.verdict == "block":
        response_status = "denied"
        execution_state = "denied"
    elif policy_decision.requires_review:
        response_status = "queued_for_review"
        execution_state = "held"
    elif verdict == "allow":
        response_status = "completed"
        execution_state = "executed"
    else:
        response_status = "denied"
        execution_state = "failed"

    return {
        "execution_id": policy_decision.decision_id,
        "trace_id": trace_id,
        "response_status": response_status,
        "execution_state": execution_state,
        "policy_verdict": verdict,
        "risk_score": risk_score,
        "risk_level": policy_decision.risk_level,
        "allow_execution": policy_decision.allow_execution and verdict == "allow",
        "requires_review": policy_decision.requires_review,
        "matched_rules": [match.to_dict() for match in policy_decision.matched_rules],
        "reasons": list(policy_decision.reasons),
        "target": payload.target,
        "action_type": payload.action_type,
        "file_path": payload.file_path,
    }
