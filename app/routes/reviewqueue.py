from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator

from app.review.reviewqueueservice import (
    ReviewPriority,
    ReviewQueueItem,
    ReviewQueueService,
    ReviewSource,
    ReviewStatus,
)

router = APIRouter(prefix="/api/review-queue", tags=["review-queue"])


class ReviewQueueListResponse(BaseModel):
    items: list[ReviewQueueItem] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class ReviewQueueCreateRequest(BaseModel):
    source: ReviewSource
    source_id: str = Field(..., min_length=1)
    priority: ReviewPriority = ReviewPriority.MEDIUM
    title: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("source_id", "title", "summary")
    @classmethod
    def _validate_non_blank_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("reasons")
    @classmethod
    def _validate_reasons(cls, value: list[str]) -> list[str]:
        normalized = [reason.strip() for reason in value if reason.strip()]
        return normalized


class ReviewQueueAssignRequest(BaseModel):
    reviewer_id: str = Field(..., min_length=1)

    @field_validator("reviewer_id")
    @classmethod
    def _validate_reviewer_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized


class ReviewQueueDismissRequest(BaseModel):
    reason: str | None = None

    @field_validator("reason")
    @classmethod
    def _validate_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


@lru_cache(maxsize=1)
def get_review_queue_service() -> ReviewQueueService:
    return ReviewQueueService()


def _get_item_or_404(review_id: str) -> ReviewQueueItem:
    item = get_review_queue_service().get(review_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"review item not found: {review_id}",
        )
    return item


def _parse_review_status(status_filter: str | None) -> ReviewStatus | None:
    if status_filter is None:
        return None
    normalized = status_filter.strip().lower()
    if not normalized:
        return None
    try:
        return ReviewStatus(normalized)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid status filter: {status_filter}",
        ) from exc


@router.get("", response_model=ReviewQueueListResponse)
def list_review_queue(
    status_filter: Annotated[str | None, Query(default=None, alias="status")] = None,
    assigned_to: str | None = Query(default=None),
) -> ReviewQueueListResponse:
    service = get_review_queue_service()
    normalized_assigned_to = assigned_to.strip() if assigned_to is not None else None
    if normalized_assigned_to == "":
        normalized_assigned_to = None
    items = service.list_items(
        status=_parse_review_status(status_filter),
        assigned_to=normalized_assigned_to,
    )
    return ReviewQueueListResponse(
        items=items,
        counts=service.counts(),
    )


@router.post(
    "",
    response_model=ReviewQueueItem,
    status_code=status.HTTP_201_CREATED,
)
def create_review_item(payload: ReviewQueueCreateRequest) -> ReviewQueueItem:
    return get_review_queue_service().enqueue(
        source=payload.source,
        source_id=payload.source_id,
        priority=payload.priority,
        title=payload.title,
        summary=payload.summary,
        reasons=payload.reasons,
        evidence=payload.evidence,
    )


@router.get("/{review_id}", response_model=ReviewQueueItem)
def get_review_item(review_id: str) -> ReviewQueueItem:
    return _get_item_or_404(review_id)


@router.post("/{review_id}/assign", response_model=ReviewQueueItem)
def assign_review_item(
    review_id: str,
    payload: ReviewQueueAssignRequest,
) -> ReviewQueueItem:
    _get_item_or_404(review_id)
    return get_review_queue_service().assign(review_id, payload.reviewer_id)


@router.post("/{review_id}/complete", response_model=ReviewQueueItem)
def complete_review_item(review_id: str) -> ReviewQueueItem:
    _get_item_or_404(review_id)
    return get_review_queue_service().complete(review_id)


@router.post("/{review_id}/dismiss", response_model=ReviewQueueItem)
def dismiss_review_item(
    review_id: str,
    payload: ReviewQueueDismissRequest,
) -> ReviewQueueItem:
    _get_item_or_404(review_id)
    return get_review_queue_service().dismiss(review_id, payload.reason)


@router.post("/{review_id}/reopen", response_model=ReviewQueueItem)
def reopen_review_item(review_id: str) -> ReviewQueueItem:
    _get_item_or_404(review_id)
    return get_review_queue_service().reopen(review_id)


@router.post("/{review_id}/claim", response_model=ReviewQueueItem, include_in_schema=False)
def claim_review_item(
    review_id: str,
    payload: ReviewQueueAssignRequest,
) -> ReviewQueueItem:
    _get_item_or_404(review_id)
    return get_review_queue_service().assign(review_id, payload.reviewer_id)


@router.post("/claim-next", response_model=ReviewQueueItem)
def claim_next_review_item(payload: ReviewQueueAssignRequest) -> ReviewQueueItem:
    item = get_review_queue_service().claim_next(payload.reviewer_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no pending review items available",
        )
    return item


@router.delete(
    "/{review_id}",
    status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
    response_model=None,
)
def delete_review_item(review_id: str) -> Response:
    _get_item_or_404(review_id)
    raise HTTPException(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        detail="review queue items cannot be deleted",
    )