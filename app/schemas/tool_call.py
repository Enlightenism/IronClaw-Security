from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ToolCallRiskLevel(str, Enum):
    """Assessed risk level for a tool call."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ToolCallVerdict(str, Enum):
    """Enforcement decision returned after inspecting a tool call."""

    allow = "allow"
    warn = "warn"
    quarantine = "quarantine"
    block = "block"
    audit = "audit"


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ToolCallRequest(BaseModel):
    """Inbound tool call submitted by an agent for security inspection."""

    model_config = ConfigDict(from_attributes=True)

    tool_name: str = Field(..., description="Name of the tool being invoked")
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the tool",
    )
    calling_agent_id: str | None = Field(
        None,
        description="Identifier of the agent submitting this call",
    )
    session_id: str | None = Field(
        None,
        description="Session context in which this call is being made",
    )
    calling_context: str | None = Field(
        None,
        description="Optional freeform context string for richer inspection",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_name")
    @classmethod
    def tool_name_must_be_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("tool_name must be a non-empty string")
        return v.strip()

    @field_validator("tool_args")
    @classmethod
    def tool_args_must_be_dict(cls, v: Any) -> dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("tool_args must be a dictionary")
        return v


class ToolCallInspectRequest(BaseModel):
    """Extended inspection request that wraps ToolCallRequest with policy context."""

    model_config = ConfigDict(from_attributes=True)

    tool_name: str = Field(..., description="Name of the tool being invoked")
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the tool",
    )
    calling_agent_id: str | None = Field(
        None,
        description="Identifier of the agent submitting this call",
    )
    session_id: str | None = Field(
        None,
        description="Session context in which this call is being made",
    )
    enforce: bool = Field(
        True,
        description="When False the verdict is computed but never blocks execution",
    )
    policy_version: str | None = Field(
        None,
        description="Pin evaluation to a specific policy version",
    )
    calling_context: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_name")
    @classmethod
    def tool_name_must_be_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("tool_name must be a non-empty string")
        return v.strip()

    @field_validator("tool_args")
    @classmethod
    def tool_args_must_be_dict(cls, v: Any) -> dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("tool_args must be a dictionary")
        return v


# ---------------------------------------------------------------------------
# Response / verdict schemas
# ---------------------------------------------------------------------------


class ToolCallVerdictResponse(BaseModel):
    """Structured verdict returned after inspecting a tool call."""

    model_config = ConfigDict(from_attributes=True)

    verdict: ToolCallVerdict
    tool_name: str
    risk_level: ToolCallRiskLevel = ToolCallRiskLevel.info
    risk_score: int = Field(0, ge=0, le=100)
    matched_rules: list[str] = Field(
        default_factory=list,
        description="rule_ids that matched during evaluation",
    )
    categories: list[str] = Field(default_factory=list)
    reasoning: str | None = None
    blocked: bool = False
    policy_version: str | None = None
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Audit / log schema
# ---------------------------------------------------------------------------


class ToolCallLog(BaseModel):
    """Persisted audit record for a single tool call inspection."""

    model_config = ConfigDict(from_attributes=True)

    log_id: str | None = None
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    calling_agent_id: str | None = None
    session_id: str | None = None
    verdict: ToolCallVerdict
    risk_level: ToolCallRiskLevel = ToolCallRiskLevel.info
    risk_score: int = Field(0, ge=0, le=100)
    matched_rules: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    reasoning: str | None = None
    blocked: bool = False
    policy_version: str | None = None
    calling_context: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    logged_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
