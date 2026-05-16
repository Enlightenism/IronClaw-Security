from typing import Literal

from pydantic import BaseModel, Field

SandboxLane = Literal[
    "none",
    "prompt_injection",
    "code_execution",
    "exfiltration",
    "high_risk_misc",
]


class ScanRequest(BaseModel):
    target_type: Literal["prompt", "github_repo", "skill", "archive", "url", "text", "local_path"]
    target_value: str = Field(min_length=1, max_length=5000)
    client_id: str | None = None


class ScanResult(BaseModel):
    scan_id: str | None = None
    verdict: Literal["allow", "warn", "quarantine", "block"]
    summary: str
    target_type: str
    target_value: str
    risk_score: int = Field(ge=0, le=100)
    matched_patterns: list[str] = Field(default_factory=list)
    risky_files: list[str] = Field(default_factory=list)
    checks_loaded: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    quarantine_reason: str | None = None
    review_status: Literal["none", "pending", "approved", "rejected"] = "none"
    untrusted: bool = False
    sandbox_lane: SandboxLane = "none"
    timestamp: str | None = None
    max_severity: Literal["low", "medium", "high", "critical"] | None = None
    primary_category: str | None = None
    explanation: str | None = None
    client_id: str | None = None


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(min_length=1, max_length=100)


class BatchScanResponse(BaseModel):
    count: int
    items: list[ScanResult]


class ScanHistoryItem(ScanResult):
    timestamp: str


class ScanHistoryResponse(BaseModel):
    count: int
    items: list[ScanHistoryItem]
