from typing import Literal
from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    target_type: Literal["github_repo", "skill", "archive", "url", "text", "local_path"]
    target_value: str = Field(min_length=1, max_length=5000)

class ScanResult(BaseModel):
    scan_id: str | None = None
    verdict: Literal["allow", "warn", "quarantine", "block"]
    summary: str
    target_type: str
    target_value: str
    risk_score: int = Field(ge=0, le=100)
    matched_patterns: list[str] = []
    risky_files: list[str] = []
    checks_loaded: list[str] = []
    failed_checks: list[str] = []

class ScanHistoryItem(ScanResult):
    timestamp: str

class ScanHistoryResponse(BaseModel):
    count: int
    items: list[ScanHistoryItem]
