from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies.api_key import require_api_key
from app.models.review_queue import (
    ReviewActionRequest,
    ReviewItemResponse,
    ReviewQueueSummaryResponse,
)
from app.services.review_queue import (
    approve_review_item,
    get_all_reviews,
    get_pending_reviews,
    get_review_by_id,
    get_review_summary,
    reject_review_item,
)

router = APIRouter(
    prefix="/guard/reviews",
    tags=["review-queue"],
    dependencies=[Depends(require_api_key)],
)


def _not_found_review_item() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Review item not found",
    )


@router.get("/summary", response_model=ReviewQueueSummaryResponse)
def read_review_summary() -> ReviewQueueSummaryResponse:
    return ReviewQueueSummaryResponse(**get_review_summary())


@router.get("", response_model=list[ReviewItemResponse])
def read_all_reviews() -> list[ReviewItemResponse]:
    return [ReviewItemResponse(**item) for item in get_all_reviews()]


@router.get("/pending", response_model=list[ReviewItemResponse])
def read_pending_reviews() -> list[ReviewItemResponse]:
    return [ReviewItemResponse(**item) for item in get_pending_reviews()]


@router.get("/{review_id}", response_model=ReviewItemResponse)
def read_review(review_id: str) -> ReviewItemResponse:
    item = get_review_by_id(review_id)
    if item is None:
        raise _not_found_review_item()
    return ReviewItemResponse(**item)


@router.post("/{review_id}/approve", response_model=ReviewItemResponse)
def approve_review(
    review_id: str,
    payload: ReviewActionRequest,
) -> ReviewItemResponse:
    item = approve_review_item(review_id, payload)
    if item is None:
        raise _not_found_review_item()
    return ReviewItemResponse(**item)


@router.post("/{review_id}/reject", response_model=ReviewItemResponse)
def reject_review(
    review_id: str,
    payload: ReviewActionRequest,
) -> ReviewItemResponse:
    item = reject_review_item(review_id, payload)
    if item is None:
        raise _not_found_review_item()
    return ReviewItemResponse(**item)