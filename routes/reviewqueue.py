from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from review.reviewqueueservice import ReviewQueueItem, ReviewQueueService, ReviewStatus

router = APIRouter(prefix="/review-queue", tags=["review-queue"])

_review_queue_service = ReviewQueueService()


class ReviewQueueListResponse(BaseModel):
    items: list[ReviewQueueItem]
    counts: dict[str, int]


class ClaimNextRequest(BaseModel):
    reviewer_id: str = Field(..., min_length=1, description="Analyst claiming next item")


class AssignReviewRequest(BaseModel):
    reviewer_id: str = Field(..., min_length=1, description="Analyst assignment target")


class DismissReviewRequest(BaseModel):
    reason: str | None = Field(default=None, description="Optional dismissal reason")


def get_review_queue_service() -> ReviewQueueService:
    return _review_queue_service


@router.get("", response_model=ReviewQueueListResponse)
def list_review_queue(
    status: ReviewStatus | None = None,
    assigned_to: str | None = None,
) -> ReviewQueueListResponse:
    service = get_review_queue_service()
    items = service.list_items(status=status, assigned_to=assigned_to)
    return ReviewQueueListResponse(items=items, counts=service.counts())


@router.get("/{review_id}", response_model=ReviewQueueItem)
def get_review_queue_item(review_id: str) -> ReviewQueueItem:
    item = get_review_queue_service().get(review_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"review item not found: {review_id}")
    return item


@router.post("/claim-next", response_model=ReviewQueueItem)
def claim_next_review(payload: ClaimNextRequest) -> ReviewQueueItem:
    item = get_review_queue_service().claim_next(payload.reviewer_id)
    if item is None:
        raise HTTPException(status_code=404, detail="no pending review items available")
    return item


@router.post("/{review_id}/assign", response_model=ReviewQueueItem)
def assign_review_item(review_id: str, payload: AssignReviewRequest) -> ReviewQueueItem:
    service = get_review_queue_service()
    try:
        return service.assign(review_id, payload.reviewer_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{review_id}/complete", response_model=ReviewQueueItem)
def complete_review_item(review_id: str) -> ReviewQueueItem:
    service = get_review_queue_service()
    try:
        return service.complete(review_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{review_id}/dismiss", response_model=ReviewQueueItem)
def dismiss_review_item(
    review_id: str,
    payload: DismissReviewRequest,
) -> ReviewQueueItem:
    service = get_review_queue_service()
    try:
        return service.dismiss(review_id, reason=payload.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{review_id}/reopen", response_model=ReviewQueueItem)
def reopen_review_item(review_id: str) -> ReviewQueueItem:
    service = get_review_queue_service()
    try:
        return service.reopen(review_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc