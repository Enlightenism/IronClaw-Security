from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.review.reviewqueueservice import ReviewQueueItem, ReviewStatus
from app.routes.reviewqueue import get_review_queue_service

router = APIRouter(prefix="/api/ui/reviews", tags=["ui-review-detail"])


class ReviewDetailField(BaseModel):
    key: str
    label: str
    value: str | None = None


class ReviewEvidenceItem(BaseModel):
    index: int
    data: dict[str, Any] = Field(default_factory=dict)


class ReviewDetailAction(BaseModel):
    key: str
    label: str
    method: str = "POST"
    api_path: str
    body: dict[str, Any] = Field(default_factory=dict)
    style: str = "default"


class ReviewDetailResponse(BaseModel):
    review_id: str
    title: str
    summary: str
    status: str
    priority: str
    source: str
    source_id: str
    assigned_to: str | None = None
    created_at: str
    updated_at: str
    completed_at: str | None = None
    fields: list[ReviewDetailField] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[ReviewEvidenceItem] = Field(default_factory=list)
    actions: list[ReviewDetailAction] = Field(default_factory=list)


def _build_actions(item: ReviewQueueItem) -> list[ReviewDetailAction]:
    actions: list[ReviewDetailAction] = []

    if item.status == ReviewStatus.PENDING:
        actions.append(
            ReviewDetailAction(
                key="assign",
                label="Assign to analyst",
                api_path=f"/api/review-queue/{item.review_id}/assign",
                body={"reviewer_id": "analyst-1"},
                style="primary",
            ),
        )

    if item.status == ReviewStatus.IN_PROGRESS:
        actions.append(
            ReviewDetailAction(
                key="complete",
                label="Complete review",
                api_path=f"/api/review-queue/{item.review_id}/complete",
                body={},
                style="success",
            ),
        )
        actions.append(
            ReviewDetailAction(
                key="dismiss",
                label="Dismiss review",
                api_path=f"/api/review-queue/{item.review_id}/dismiss",
                body={"reason": "dismissed-by-analyst"},
                style="danger",
            ),
        )

    if item.status in {ReviewStatus.COMPLETED, ReviewStatus.DISMISSED}:
        actions.append(
            ReviewDetailAction(
                key="reopen",
                label="Reopen review",
                api_path=f"/api/review-queue/{item.review_id}/reopen",
                body={},
                style="default",
            ),
        )

    return actions


def _build_fields(item: ReviewQueueItem) -> list[ReviewDetailField]:
    return [
        ReviewDetailField(key="review_id", label="Review ID", value=item.review_id),
        ReviewDetailField(key="source", label="Source", value=item.source.value),
        ReviewDetailField(key="source_id", label="Source ID", value=item.source_id),
        ReviewDetailField(key="priority", label="Priority", value=item.priority.value),
        ReviewDetailField(key="status", label="Status", value=item.status.value),
        ReviewDetailField(key="assigned_to", label="Assigned To", value=item.assigned_to),
        ReviewDetailField(key="created_at", label="Created At", value=item.created_at),
        ReviewDetailField(key="updated_at", label="Updated At", value=item.updated_at),
        ReviewDetailField(key="completed_at", label="Completed At", value=item.completed_at),
    ]


@router.get("/{review_id}", response_model=ReviewDetailResponse, summary="Get review detail")
def get_review_detail(review_id: str) -> ReviewDetailResponse:
    normalized_review_id = review_id.strip()
    if not normalized_review_id:
        raise HTTPException(status_code=404, detail="review item not found")

    service = get_review_queue_service()
    item = service.get(normalized_review_id)

    if item is None:
        raise HTTPException(status_code=404, detail=f"review item not found: {normalized_review_id}")

    return ReviewDetailResponse(
        review_id=item.review_id,
        title=item.title,
        summary=item.summary,
        status=item.status.value,
        priority=item.priority.value,
        source=item.source.value,
        source_id=item.source_id,
        assigned_to=item.assigned_to,
        created_at=item.created_at,
        updated_at=item.updated_at,
        completed_at=item.completed_at,
        fields=_build_fields(item),
        reasons=list(item.reasons),
        evidence=[ReviewEvidenceItem(index=index + 1, data=dict(evidence)) for index, evidence in enumerate(item.evidence)],
        actions=_build_actions(item),
    )
