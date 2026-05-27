from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator

from app.review.reviewqueueservice import ReviewQueueService, build_review_queue_service

router = APIRouter(prefix="/api/review-queue", tags=["review-queue"])

_VALID_STATUSES = {"pending", "in_review", "completed", "rejected", "cancelled"}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}


class ReviewQueueListResponse(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class ReviewQueueCreateRequest(BaseModel):
    source: str = Field(..., min_length=1)
    source_id: str = Field(..., min_length=1)
    priority: str = "medium"
    title: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("source_id", "title", "summary", "source")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("priority")
    @classmethod
    def _valid_priority(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in _VALID_PRIORITIES:
            raise ValueError(f"priority must be one of {sorted(_VALID_PRIORITIES)}")
        return normalized

    @field_validator("reasons")
    @classmethod
    def _clean_reasons(cls, value: list[str]) -> list[str]:
        return [r.strip() for r in value if r.strip()]


class ReviewQueueAssignRequest(BaseModel):
    reviewer_id: str = Field(..., min_length=1)

    @field_validator("reviewer_id")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized


class ReviewQueueDismissRequest(BaseModel):
    reason: str | None = None

    @field_validator("reason")
    @classmethod
    def _clean_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class ReviewQueueCompleteRequest(BaseModel):
    verdict: str = "completed"
    notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@lru_cache(maxsize=1)
def get_review_queue_service() -> ReviewQueueService:
    return build_review_queue_service()


def _get_item_or_404(review_id: str) -> dict[str, Any]:
    item = get_review_queue_service().get(review_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"review item not found: {review_id}",
        )
    return item


def _parse_status(status_filter: str | None) -> str | None:
    if status_filter is None:
        return None
    normalized = status_filter.strip().lower()
    if not normalized:
        return None
    if normalized not in _VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid status filter: {status_filter}",
        )
    return normalized


@router.get("", response_model=ReviewQueueListResponse)
def list_review_queue(
    status_filter: str | None = Query(default=None, alias="status"),
    assigned_to: str | None = Query(default=None),
) -> ReviewQueueListResponse:
    service = get_review_queue_service()
    normalized_assigned_to = assigned_to.strip() if assigned_to else None
    items = service.list_reviews(
        status=_parse_status(status_filter),
        assigned_to=normalized_assigned_to or None,
    )
    summary = service.summarize()
    return ReviewQueueListResponse(
        items=items,
        counts={
            "total": summary.get("total", 0),
            "pending": summary.get("pending", 0),
            "in_review": summary.get("in_review", 0),
            "completed": summary.get("completed", 0),
            "rejected": summary.get("rejected", 0),
            "cancelled": summary.get("cancelled", 0),
        },
    )


@router.post("", status_code=status.HTTP_201_CREATED)
def create_review_item(payload: ReviewQueueCreateRequest) -> dict[str, Any]:
    return get_review_queue_service().submit(
        {
            "source": payload.source,
            "incident_id": payload.source_id,
            "item_type": payload.source,
            "priority": payload.priority,
            "title": payload.title,
            "summary": payload.summary,
            "tags": payload.reasons,
            "evidence": payload.evidence,
        }
    )


@router.get("/{review_id}")
def get_review_item(review_id: str) -> dict[str, Any]:
    return _get_item_or_404(review_id)


@router.post("/{review_id}/assign")
def assign_review_item(
    review_id: str,
    payload: ReviewQueueAssignRequest,
) -> dict[str, Any]:
    _get_item_or_404(review_id)
    result = get_review_queue_service().assign_review(review_id, payload.reviewer_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"review item not found: {review_id}",
        )
    return result


@router.post("/{review_id}/complete")
def complete_review_item(
    review_id: str,
    payload: ReviewQueueCompleteRequest = ReviewQueueCompleteRequest(),
) -> dict[str, Any]:
    _get_item_or_404(review_id)
    result = get_review_queue_service().complete_review(
        review_id,
        verdict=payload.verdict,
        notes=payload.notes,
        metadata=payload.metadata,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"review item not found: {review_id}",
        )
    return result


@router.post("/{review_id}/dismiss")
def dismiss_review_item(
    review_id: str,
    payload: ReviewQueueDismissRequest,
) -> dict[str, Any]:
    _get_item_or_404(review_id)
    result = get_review_queue_service().reject_review(
        review_id,
        notes=payload.reason,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"review item not found: {review_id}",
        )
    return result


@router.post("/{review_id}/reopen")
def reopen_review_item(review_id: str) -> dict[str, Any]:
    item = _get_item_or_404(review_id)
    item = dict(item)
    item["status"] = "pending"
    return get_review_queue_service().submit(item)


@router.post("/{review_id}/claim", include_in_schema=False)
def claim_review_item(
    review_id: str,
    payload: ReviewQueueAssignRequest,
) -> dict[str, Any]:
    _get_item_or_404(review_id)
    result = get_review_queue_service().assign_review(review_id, payload.reviewer_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"review item not found: {review_id}",
        )
    return result


@router.post("/claim-next")
def claim_next_review_item(payload: ReviewQueueAssignRequest) -> dict[str, Any]:
    service = get_review_queue_service()
    pending = service.list_reviews(status="pending", limit=1)
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no pending review items available",
        )
    review_id = pending[0].get("review_id") or pending[0].get("id", "")
    result = service.assign_review(review_id, payload.reviewer_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no pending review items available",
        )
    return result


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
