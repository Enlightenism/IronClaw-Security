from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.review.reviewqueueservice import ReviewPriority, ReviewQueueItem, ReviewStatus
from app.routes.reviewqueue import get_review_queue_service

router = APIRouter(prefix="/api/ui/review-queue", tags=["ui-review-queue"])


class ReviewQueueFilterOption(BaseModel):
    value: str
    label: str


class ReviewQueueRowAction(BaseModel):
    key: str
    label: str
    method: str = "GET"
    href: str | None = None
    api_path: str | None = None
    body: dict[str, Any] | None = None
    style: str = "default"


class ReviewQueueRow(BaseModel):
    review_id: str
    title: str
    summary: str
    source: str
    source_id: str
    priority: str
    status: str
    assigned_to: str | None = None
    reasons: list[str] = Field(default_factory=list)
    evidence_count: int = 0
    created_at: str
    updated_at: str
    completed_at: str | None = None
    detail_href: str
    actions: list[ReviewQueueRowAction] = Field(default_factory=list)


class ReviewQueueFilters(BaseModel):
    statuses: list[ReviewQueueFilterOption] = Field(default_factory=list)
    priorities: list[ReviewQueueFilterOption] = Field(default_factory=list)


class ReviewQueueSummaryCard(BaseModel):
    key: str
    label: str
    count: int


class ReviewQueuePageResponse(BaseModel):
    title: str
    description: str
    filters: ReviewQueueFilters
    summary_cards: list[ReviewQueueSummaryCard] = Field(default_factory=list)
    items: list[ReviewQueueRow] = Field(default_factory=list)
    total_items: int


def _labelize(value: str) -> str:
    return value.replace("_", " ").title()


def _parse_review_status(value: str | None) -> ReviewStatus | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    try:
        return ReviewStatus(normalized)
    except ValueError as exc:
        allowed = ", ".join(status.value for status in ReviewStatus)
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{value}'. Expected one of: {allowed}.",
        ) from exc


def _build_row(item: ReviewQueueItem) -> ReviewQueueRow:
    detail_href = f"/reviews/{item.review_id}"
    actions: list[ReviewQueueRowAction] = [
        ReviewQueueRowAction(
            key="open",
            label="Open review",
            method="GET",
            href=detail_href,
            style="primary",
        )
    ]

    if item.status == ReviewStatus.PENDING:
        actions.append(
            ReviewQueueRowAction(
                key="claim",
                label="Claim",
                method="POST",
                api_path="/api/review-queue/claim-next",
                body={"reviewer_id": "analyst-1"},
                style="default",
            )
        )

    if item.status == ReviewStatus.IN_PROGRESS:
        actions.append(
            ReviewQueueRowAction(
                key="complete",
                label="Complete",
                method="POST",
                api_path=f"/api/review-queue/{item.review_id}/complete",
                body={},
                style="success",
            )
        )
        actions.append(
            ReviewQueueRowAction(
                key="dismiss",
                label="Dismiss",
                method="POST",
                api_path=f"/api/review-queue/{item.review_id}/dismiss",
                body={"reason": "dismissed-by-analyst"},
                style="danger",
            )
        )

    return ReviewQueueRow(
        review_id=item.review_id,
        title=item.title,
        summary=item.summary,
        source=item.source.value,
        source_id=item.source_id,
        priority=item.priority.value,
        status=item.status.value,
        assigned_to=item.assigned_to,
        reasons=list(item.reasons),
        evidence_count=len(item.evidence),
        created_at=item.created_at,
        updated_at=item.updated_at,
        completed_at=item.completed_at,
        detail_href=detail_href,
        actions=actions,
    )


@router.get("", response_model=ReviewQueuePageResponse, summary="Get review queue page")
def get_review_queue_page(
    status: str | None = Query(default=None),
    assigned_to: str | None = Query(default=None),
) -> ReviewQueuePageResponse:
    service = get_review_queue_service()

    status_enum = _parse_review_status(status)
    normalized_assigned_to = assigned_to.strip() if assigned_to and assigned_to.strip() else None

    items = service.list_items(status=status_enum, assigned_to=normalized_assigned_to)
    counts = service.counts()

    return ReviewQueuePageResponse(
        title="Review Queue",
        description="Analyst queue for escalated review items that require human triage.",
        filters=ReviewQueueFilters(
            statuses=[
                ReviewQueueFilterOption(value=status_member.value, label=_labelize(status_member.value))
                for status_member in ReviewStatus
            ],
            priorities=[
                ReviewQueueFilterOption(value=priority.value, label=_labelize(priority.value))
                for priority in ReviewPriority
            ],
        ),
        summary_cards=[
            ReviewQueueSummaryCard(key="pending", label="Pending", count=counts.get("pending", 0)),
            ReviewQueueSummaryCard(
                key="in_progress",
                label="In Progress",
                count=counts.get("in_progress", 0),
            ),
            ReviewQueueSummaryCard(
                key="completed",
                label="Completed",
                count=counts.get("completed", 0),
            ),
            ReviewQueueSummaryCard(
                key="dismissed",
                label="Dismissed",
                count=counts.get("dismissed", 0),
            ),
        ],
        items=[_build_row(item) for item in items],
        total_items=len(items),
    )