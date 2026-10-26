from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.services.action_guard import ActionType


class ActionReason(BaseModel):
    source: Literal["policy", "scan", "ai"]
    label: str
    details: str
    score: float | None = None


class ActionGuardRequest(BaseModel):
    action_type: ActionType
    target: str = Field(..., min_length=1)
    content: str = Field(default="")
    client_id: str | None = Field(default=None)
    session_id: str | None = Field(default=None)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Target must not be blank")
        return normalized

    @field_validator("content")
    @classmethod
    def normalize_content(cls, value: str) -> str:
        return value.strip()


class ActionPolicyResponse(BaseModel):
    action_type: ActionType
    target: str
    policy_mode: Literal["allow", "review", "block"]
    verdict: Literal["allow", "warn", "quarantine", "block"]
    summary: str
    should_halt: bool
    should_warn: bool
    client_id: str | None = None
    session_id: str | None = None
    reasons: list[ActionReason] = Field(default_factory=list)


class ActionGuardResponse(BaseModel):
    action_type: ActionType
    verdict: Literal["allow", "warn", "quarantine", "block"]
    scan_id: str | None
    summary: str
    risk_score: int
    matched_patterns: list[str]
    target: str
    content: str
    should_halt: bool
    should_warn: bool
    client_id: str | None = None
    session_id: str | None = None
    reasons: list[ActionReason] = Field(default_factory=list)


class ActionDecisionResponse(BaseModel):
    action_type: ActionType
    target: str
    content: str
    policy_mode: Literal["allow", "review", "block"] | None = None
    verdict: Literal["allow", "warn", "quarantine", "block"]
    summary: str
    risk_score: int
    matched_patterns: list[str]
    scan_id: str | None = None
    should_halt: bool
    should_warn: bool
    decision_source: Literal["policy", "scan", "policy_and_scan"]
    client_id: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    categories: list[str] = Field(default_factory=list)
    drift_report: dict[str, Any] | None = None
    reasons: list[ActionReason] = Field(default_factory=list)
    # Guard telemetry — full EnforcedVerdict surface
    guard_verdict: str | None = None
    guard_risk_score: int | None = None
    guard_confidence: float | None = None
    guard_latency_ms: float | None = None
    guard_model_name: str | None = None
    guard_signals: list[str] = Field(default_factory=list)
    guard_summary: str | None = None
    guard_decided_at: str | None = None
    enforced_at: str | None = None
