from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ActionType = Literal[
    "http_fetch",
    "shell_command",
    "tool_call",
    "file_write",
    "browser_open",
]
VerdictType = Literal["allow", "block"]
PolicyMode = Literal["allow", "review", "block"]
ReasonSource = Literal["policy", "scan", "ai"]
FinalDecisionSource = Literal["policy", "scan", "policy_and_scan"]


class ReasonItem(BaseModel):
    source: ReasonSource
    label: str
    details: str
    score: float | None = None


class GuardActionRequest(BaseModel):
    action_type: ActionType
    target: str = Field(..., min_length=1)
    content: str = ""
    client_id: str | None = None
    session_id: str | None = None


class GuardActionResponse(BaseModel):
    action_type: ActionType
    target: str
    content: str
    verdict: VerdictType
    summary: str
    risk_score: int
    matched_patterns: list[str]
    scan_id: str | None
    should_halt: bool
    should_warn: Literal[False]
    client_id: str | None = None
    session_id: str | None = None
    reasons: list[ReasonItem] = Field(default_factory=list)


class ActionPolicyRequest(BaseModel):
    action_type: ActionType
    target: str = Field(..., min_length=1)
    content: str = ""
    client_id: str | None = None
    session_id: str | None = None


class ActionPolicyResponse(BaseModel):
    action_type: ActionType
    target: str
    policy_mode: PolicyMode
    verdict: VerdictType
    summary: str
    should_halt: bool
    should_warn: Literal[False]
    client_id: str | None = None
    session_id: str | None = None
    reasons: list[ReasonItem] = Field(default_factory=list)


class ActionDecisionRequest(BaseModel):
    action_type: ActionType
    target: str = Field(..., min_length=1)
    content: str = ""
    client_id: str | None = None
    session_id: str | None = None


class ActionDecisionResponse(BaseModel):
    action_type: ActionType
    target: str
    content: str
    policy_mode: PolicyMode
    verdict: VerdictType
    summary: str
    risk_score: int
    matched_patterns: list[str]
    scan_id: str | None
    should_halt: bool
    should_warn: Literal[False]
    decision_source: FinalDecisionSource
    client_id: str | None = None
    session_id: str | None = None
    reasons: list[ReasonItem] = Field(default_factory=list)
