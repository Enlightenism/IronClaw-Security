from __future__ import annotations

from pydantic import BaseModel


class ActionGuardRequest(BaseModel):
    action_type: str
    target: str
    content: str = ""
    risk_score: int = 0
    client_id: str | None = None
    session_id: str | None = None
    file_path: str | None = None


class ActionGuardResponse(BaseModel):
    action_type: str
    target: str
    policy_verdict: str
    risk_score: int
    should_halt: bool
    should_warn: bool
    reason: str | None = None


class ActionPolicyResponse(BaseModel):
    action_type: str
    target: str
    policy_verdict: str
    risk_score: int
    should_execute: bool
    halted_by_boundary: bool
    reason: str | None = None


class ActionDecisionResponse(BaseModel):
    action_type: str
    target: str
    verdict: str
    risk_score: int
    should_halt: bool
    should_warn: bool
    decision_source: str | None = None
    reason: str | None = None
