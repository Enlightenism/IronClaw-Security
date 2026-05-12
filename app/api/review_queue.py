from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.review_queue_service import (
    approve_review,
    get_review_by_id,
    get_review_queue_summary,
    list_all_reviews,
    list_pending_reviews,
    reject_review,
)

router = APIRouter(prefix="/reviews", tags=["review-queue"])


class ReviewActionRequest(BaseModel):
    reviewed_by: str = Field(..., min_length=1)
    review_note: str | None = None


class ReviewQueueSummaryResponse(BaseModel):
    total_items: int
    pending_items: int
    approved_items: int
    rejected_items: int
    critical_items: int
    high_items: int
    medium_items: int
    low_items: int
    updated_at: str


class ReviewItemResponse(BaseModel):
    review_id: str
    actor_id: str
    action_type: str
    target: str
    verdict: str
    risk_score: int
    priority: str
    reason: str
    status: str
    file_path: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    reviewed_at: str | None = None
    reviewed_by: str | None = None
    review_note: str | None = None


@router.get("/summary", response_model=ReviewQueueSummaryResponse)
def get_review_summary() -> ReviewQueueSummaryResponse:
    summary = get_review_queue_summary()
    return ReviewQueueSummaryResponse(**summary)


@router.get("", response_model=list[ReviewItemResponse])
def get_all_reviews() -> list[ReviewItemResponse]:
    items = list_all_reviews()
    return [ReviewItemResponse(**item) for item in items]


@router.get("/pending", response_model=list[ReviewItemResponse])
def get_pending_reviews() -> list[ReviewItemResponse]:
    items = list_pending_reviews()
    return [ReviewItemResponse(**item) for item in items]


@router.get("/{review_id}", response_model=ReviewItemResponse)
def get_review(review_id: str) -> ReviewItemResponse:
    item = get_review_by_id(review_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Review item not found")
    return ReviewItemResponse(**item)


@router.post("/{review_id}/approve", response_model=ReviewItemResponse)
def approve_review_item(
    review_id: str,
    payload: ReviewActionRequest,
) -> ReviewItemResponse:
    try:
        item = approve_review(
            review_id=review_id,
            reviewed_by=payload.reviewed_by,
            review_note=payload.review_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ReviewItemResponse(**item)


@router.post("/{review_id}/reject", response_model=ReviewItemResponse)
def reject_review_item(
    review_id: str,
    payload: ReviewActionRequest,
) -> ReviewItemResponse:
    try:
        item = reject_review(
            review_id=review_id,
            reviewed_by=payload.reviewed_by,
            review_note=payload.review_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ReviewItemResponse(**item)