from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.review.reviewqueueservice import ReviewQueueService
from app.routes.reviewqueue import get_review_queue_service

router = APIRouter(prefix="/api/ui/review-queue", tags=["ui-review-queue"])

_VALID_STATUSES = {"pending", "in_review", "completed", "rejected", "cancelled"}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}


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


def _s(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _labelize(value: str) -> str:
    return value.replace("_", " ").title()


def _parse_status(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized not in _VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{value}'. Expected one of: {', '.join(sorted(_VALID_STATUSES))}.",
        )
    return normalized


def _build_row(item: dict[str, Any]) -> ReviewQueueRow:
    review_id = _s(item.get("review_id")) or _s(item.get("id"))
    detail_href = f"/reviews/{review_id}"
    status = _s(item.get("status")) or "pending"

    actions: list[ReviewQueueRowAction] = [
        ReviewQueueRowAction(
            key="open",
            label="Open review",
            method="GET",
            href=detail_href,
            style="primary",
        ),
    ]

    if status == "pending":
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

    if status == "in_review":
        actions.append(
            ReviewQueueRowAction(
                key="complete",
                label="Complete",
                method="POST",
                api_path=f"/api/review-queue/{review_id}/complete",
                body={},
                style="success",
            )
        )
        actions.append(
            ReviewQueueRowAction(
                key="dismiss",
                label="Dismiss",
                method="POST",
                api_path=f"/api/review-queue/{review_id}/dismiss",
                body={"reason": "dismissed-by-analyst"},
                style="danger",
            )
        )

    evidence_raw = item.get("evidence") or []
    reasons_raw = item.get("tags") or item.get("reasons") or []

    return ReviewQueueRow(
        review_id=review_id,
        title=_s(item.get("title")) or "Review",
        summary=_s(item.get("summary")),
        source=_s(item.get("source")) or "ironclaw",
        source_id=_s(item.get("incident_id")) or _s(item.get("quarantine_id")) or review_id,
        priority=_s(item.get("priority")) or "medium",
        status=status,
        assigned_to=_s(item.get("assigned_to")) or None,
        reasons=[str(r) for r in reasons_raw if r is not None],
        evidence_count=len(evidence_raw),
        created_at=_s(item.get("created_at")),
        updated_at=_s(item.get("updated_at")),
        completed_at=_s(item.get("completed_at")) or None,
        detail_href=detail_href,
        actions=actions,
    )


@router.get("", response_model=ReviewQueuePageResponse, summary="Get review queue page")
def get_review_queue_page(
    status: str | None = Query(default=None),
    assigned_to: str | None = Query(default=None),
) -> ReviewQueuePageResponse:
    service: ReviewQueueService = get_review_queue_service()

    parsed_status = _parse_status(status)
    normalized_assigned_to = assigned_to.strip() if assigned_to and assigned_to.strip() else None

    items = service.list_reviews(
        status=parsed_status,
        assigned_to=normalized_assigned_to,
    )
    summary = service.summarize()

    return ReviewQueuePageResponse(
        title="Review Queue",
        description="Analyst queue for escalated review items that require human triage.",
        filters=ReviewQueueFilters(
            statuses=[ReviewQueueFilterOption(value=s, label=_labelize(s)) for s in sorted(_VALID_STATUSES)],
            priorities=[ReviewQueueFilterOption(value=p, label=_labelize(p)) for p in ["critical", "high", "medium", "low"]],
        ),
        summary_cards=[
            ReviewQueueSummaryCard(key="pending", label="Pending", count=summary.get("pending", 0)),
            ReviewQueueSummaryCard(key="in_review", label="In Progress", count=summary.get("in_review", 0)),
            ReviewQueueSummaryCard(key="completed", label="Completed", count=summary.get("completed", 0)),
            ReviewQueueSummaryCard(key="rejected", label="Rejected", count=summary.get("rejected", 0)),
        ],
        items=[_build_row(item) for item in items],
        total_items=len(items),
    )
