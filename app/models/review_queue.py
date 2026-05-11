from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field

ReviewStatus = Literal["pending", "approved", "rejected", "quarantined"]
ReviewResolution = Literal["allow", "deny", "quarantine", "needsreview"]


class ReviewActionRequest(BaseModel):
    actor: str | None = Field(None, description="Actor performing the review action.")
    note: str | None = Field(None, description="Optional note for the review action.")


class ReviewItemResponse(BaseModel):
    reviewitemid: str
    status: ReviewStatus
    resolution: ReviewResolution
    actiontype: str
    target: str
    filepath: str
    baseriskscore: int
    adjustedriskscore: int
    reason: str
    reasons: list[dict[str, Any]] = Field(default_factory=list)
    promptinjection: dict[str, Any] = Field(default_factory=dict)
    hostilecontext: dict[str, Any] = Field(default_factory=dict)
    createdat: str
    reviewedat: str | None = None
    reviewedby: str | None = None
    reviewnote: str | None = None


class ReviewQueueSummaryResponse(BaseModel):
    total: int
    pending: int
    approved: int
    rejected: int
    quarantined: int