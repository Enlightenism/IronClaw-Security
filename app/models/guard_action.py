from __future__ import annotations

from typing import Literal

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
    policy_verdict: Literal["allow", "block"]
    risk_score: int
    should_halt: bool
    should_warn: Literal[False]
    reason: str | None = None


class ActionPolicyResponse(BaseModel):
    action_type: str
    target: str
    policy_verdict: Literal["allow", "block"]
    risk_score: int
    should_execute: bool
    halted_by_boundary: bool
    reason: str | None = None


class ActionDecisionResponse(BaseModel):
    action_type: str
    target: str
    verdict: Literal["allow", "block"]
    risk_score: int
    should_halt: bool
    should_warn: Literal[False]
    decision_source: str | None = None
    reason: str | None = None
