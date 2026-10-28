from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ReviewStatus(StrEnum):
    """Lifecycle state of a review queue item."""

    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    escalated = "escalated"


class ReviewItemType(StrEnum):
    """The kind of artifact placed in the review queue."""

    scan = "scan"
    tool_call = "tool_call"
    prompt = "prompt"
    execution = "execution"
    policy_change = "policy_change"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


class ReviewQueueItem(BaseModel):
    """A single item awaiting human or automated review."""

    model_config = ConfigDict(from_attributes=True)

    item_id: str = Field(..., description="Unique identifier for this review queue item")
    item_type: ReviewItemType = Field(
        ReviewItemType.scan,
        description="Category of artifact under review",
    )
    status: ReviewStatus = ReviewStatus.pending
    source_id: str | None = Field(
        None,
        description="ID of the originating scan, tool call, or execution record",
    )
    session_id: str | None = None
    calling_agent_id: str | None = None
    risk_score: int = Field(0, ge=0, le=100)
    verdict: str | None = Field(
        None,
        description="Original verdict that triggered queueing; historical values are preserved",
    )
    summary: str | None = None
    matched_rules: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    assigned_to: str | None = Field(
        None,
        description="Username or agent ID this item is assigned to",
    )
    priority: int = Field(
        0,
        ge=0,
        le=10,
        description="Review priority 0 (lowest) to 10 (highest)",
    )
    notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime | None = None
    resolved_at: datetime | None = None


class ReviewAssignment(BaseModel):
    """Records the assignment of a review queue item to a reviewer."""

    model_config = ConfigDict(from_attributes=True)

    assignment_id: str | None = None
    item_id: str = Field(..., description="ID of the ReviewQueueItem being assigned")
    assigned_to: str = Field(..., description="Username or agent ID of the assignee")
    assigned_by: str | None = Field(
        None,
        description="Username or system ID that made the assignment",
    )
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    notes: str | None = None


# ---------------------------------------------------------------------------
# Decision schemas
# ---------------------------------------------------------------------------


class ReviewDecisionCreate(BaseModel):
    """Payload submitted when a reviewer renders a decision on a queue item."""

    model_config = ConfigDict(from_attributes=True)

    item_id: str = Field(..., description="ID of the ReviewQueueItem being decided")
    decision: ReviewStatus = Field(
        ...,
        description="New status: approved, rejected, or escalated",
    )
    reviewer_id: str | None = Field(
        None,
        description="Username or agent ID of the reviewer",
    )
    reasoning: str | None = Field(
        None,
        description="Human-readable explanation for the decision",
    )
    override_verdict: Literal["allow", "block"] | None = Field(
        None,
        description="Optional revised verdict to apply after approval (allow/block)",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReviewDecision(BaseModel):
    """Persisted record of a review decision."""

    model_config = ConfigDict(from_attributes=True)

    decision_id: str | None = None
    item_id: str
    decision: ReviewStatus
    reviewer_id: str | None = None
    reasoning: str | None = None
    override_verdict: Literal["allow", "block"] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# List response
# ---------------------------------------------------------------------------


class ReviewQueueListResponse(BaseModel):
    """Paginated list of review queue items."""

    model_config = ConfigDict(from_attributes=True)

    count: int = Field(ge=0)
    items: list[ReviewQueueItem]
    pending_count: int = Field(0, ge=0)
    escalated_count: int = Field(0, ge=0)
