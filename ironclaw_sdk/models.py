from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ScanVerdict = Literal["allow", "warn", "quarantine", "block"]

SandboxLane = Literal[
    "none",
    "prompt_injection",
    "code_execution",
    "exfiltration",
    "high_risk_misc",
]

ReviewStatus = Literal["none", "pending", "approved", "rejected"]

MaxSeverity = Literal["low", "medium", "high", "critical"]

TargetType = Literal["prompt", "github_repo", "skill", "archive", "url", "text", "local_path"]


class ScanRequest(BaseModel):
    target_type: TargetType
    target_value: str = Field(min_length=1, max_length=5000)
    client_id: str | None = None


class ScanFlags(BaseModel):
    matched_patterns: list[str] = Field(default_factory=list)
    risky_files: list[str] = Field(default_factory=list)
    checks_loaded: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    sandbox_lane: SandboxLane = "none"
    max_severity: MaxSeverity | None = None
    primary_category: str | None = None
    untrusted: bool = False


class ScanResponse(BaseModel):
    scan_id: str | None = None
    verdict: ScanVerdict
    summary: str
    target_type: str
    target_value: str
    risk_score: int = Field(ge=0, le=100)
    matched_patterns: list[str] = Field(default_factory=list)
    risky_files: list[str] = Field(default_factory=list)
    checks_loaded: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    quarantine_reason: str | None = None
    review_status: ReviewStatus = "none"
    untrusted: bool = False
    sandbox_lane: SandboxLane = "none"
    timestamp: str | None = None
    max_severity: MaxSeverity | None = None
    primary_category: str | None = None
    explanation: str | None = None
    client_id: str | None = None


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(min_length=1, max_length=100)


class BatchScanResponse(BaseModel):
    count: int
    items: list[ScanResponse]


# ------------------------------------------------------------------
# Guard bundle models  (mirrors POST /policy/guard-bundle contract)
# ------------------------------------------------------------------


class GuardBundleRequest(BaseModel):
    """Input for the /policy/guard-bundle endpoint.

    Every slot is optional; pass only the slots relevant to the current
    agentic step. At least one slot must be non-None.
    """

    user_prompt: str | None = None
    retrieved_doc: str | None = None
    tool_output: str | None = None
    model_output: str | None = None


class GuardBundleSlotResult(BaseModel):
    """Per-slot verdict returned by the guard-bundle endpoint."""

    verdict: ScanVerdict
    summary: str
    risk_score: int = Field(ge=0, le=100)
    matched_patterns: list[str] = Field(default_factory=list)
    scan_id: str | None = None
    explanation: str | None = None


class GuardBundleResponse(BaseModel):
    """Structured response from POST /policy/guard-bundle."""

    highest_verdict: ScanVerdict
    should_halt: bool
    should_warn: bool
    user_prompt: GuardBundleSlotResult | dict[str, Any] | None = None
    retrieved_doc: GuardBundleSlotResult | dict[str, Any] | None = None
    tool_output: GuardBundleSlotResult | dict[str, Any] | None = None
    model_output: GuardBundleSlotResult | dict[str, Any] | None = None


# ------------------------------------------------------------------
# API error envelope models
# ------------------------------------------------------------------


class AuthError(BaseModel):
    status_code: int
    detail: str


class APIError(BaseModel):
    status_code: int
    body: str


__all__ = [
    "ScanVerdict",
    "SandboxLane",
    "ReviewStatus",
    "MaxSeverity",
    "TargetType",
    "ScanRequest",
    "ScanFlags",
    "ScanResponse",
    "BatchScanRequest",
    "BatchScanResponse",
    "GuardBundleRequest",
    "GuardBundleResponse",
    "GuardBundleSlotResult",
    "AuthError",
    "APIError",
]
