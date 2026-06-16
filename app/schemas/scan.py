from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enum-style Literals — single source of truth for all verdict / type values
# ---------------------------------------------------------------------------

TargetType = Literal[
    "prompt",
    "github_repo",
    "skill",
    "archive",
    "url",
    "text",
    "local_path",
]

VerdictType = Literal["allow", "warn", "quarantine", "block"]

ReviewStatusType = Literal["none", "pending", "approved", "rejected"]

SeverityType = Literal["low", "medium", "high", "critical"]

SandboxLane = Literal[
    "none",
    "prompt_injection",
    "code_execution",
    "exfiltration",
    "high_risk_misc",
]

# ---------------------------------------------------------------------------
# RiskScore — annotated type with range constraint
# ---------------------------------------------------------------------------

RiskScore = Annotated[int, Field(ge=0, le=100)]

# ---------------------------------------------------------------------------
# ScanRequest
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target_type: TargetType
    target_value: str = Field(min_length=1, max_length=5000)
    client_id: str | None = None

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, v: str) -> str:
        allowed: set[str] = {
            "prompt",
            "github_repo",
            "skill",
            "archive",
            "url",
            "text",
            "local_path",
        }
        if v not in allowed:
            raise ValueError(f"target_type must be one of {sorted(allowed)}, got '{v}'")
        return v

    @field_validator("target_value")
    @classmethod
    def validate_target_value(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("target_value must not be blank or whitespace-only")
        return v


# ---------------------------------------------------------------------------
# ScanVerdict — standalone verdict envelope (used by review/policy layers)
# ---------------------------------------------------------------------------


class ScanVerdict(BaseModel):
    verdict: VerdictType
    risk_score: RiskScore
    summary: str
    max_severity: SeverityType | None = None
    primary_category: str | None = None
    explanation: str | None = None
    matched_patterns: list[str] = Field(default_factory=list)

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        allowed: set[str] = {"allow", "warn", "quarantine", "block"}
        if v not in allowed:
            raise ValueError(f"verdict must be one of {sorted(allowed)}, got '{v}'")
        return v


# ---------------------------------------------------------------------------
# ScanResponse  (wire-contract name; ScanResult kept as alias for compat)
# ---------------------------------------------------------------------------


class ScanResponse(BaseModel):
    scan_id: str | None = None
    verdict: VerdictType
    summary: str
    target_type: str
    target_value: str
    risk_score: RiskScore
    matched_patterns: list[str] = Field(default_factory=list)
    risky_files: list[str] = Field(default_factory=list)
    checks_loaded: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    quarantine_reason: str | None = None
    review_status: ReviewStatusType = "none"
    untrusted: bool = False
    sandbox_lane: SandboxLane = "none"
    timestamp: str | None = None
    max_severity: SeverityType | None = None
    primary_category: str | None = None
    explanation: str | None = None
    client_id: str | None = None

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        allowed: set[str] = {"allow", "warn", "quarantine", "block"}
        if v not in allowed:
            raise ValueError(f"verdict must be one of {sorted(allowed)}, got '{v}'")
        return v

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"risk_score must be between 0 and 100, got {v}")
        return v

    @model_validator(mode="after")
    def auto_timestamp(self) -> ScanResponse:
        if self.timestamp is None:
            self.timestamp = datetime.now(UTC).isoformat()
        return self


# Backward-compat alias — existing code importing ScanResult keeps working
ScanResult = ScanResponse


# ---------------------------------------------------------------------------
# ScanSummary — lightweight projection for list/history endpoints
# ---------------------------------------------------------------------------


class ScanSummary(BaseModel):
    scan_id: str | None = None
    verdict: VerdictType
    risk_score: RiskScore
    target_type: str
    summary: str
    timestamp: str | None = None
    client_id: str | None = None
    max_severity: SeverityType | None = None
    primary_category: str | None = None


# ---------------------------------------------------------------------------
# ScanHistoryItem — full record with guaranteed timestamp
# ---------------------------------------------------------------------------


class ScanHistoryItem(ScanResponse):
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


# ---------------------------------------------------------------------------
# ScanHistoryListResponse  (wire-contract name; ScanHistoryResponse alias kept)
# ---------------------------------------------------------------------------


class ScanHistoryListResponse(BaseModel):
    count: int = Field(ge=0)
    items: list[ScanHistoryItem]


# Backward-compat alias
ScanHistoryResponse = ScanHistoryListResponse


# ---------------------------------------------------------------------------
# Batch contracts
# ---------------------------------------------------------------------------


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(min_length=1, max_length=100)


class BatchScanResponse(BaseModel):
    count: int = Field(ge=0)
    items: list[ScanResponse]
