from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.review.reviewqueueservice import ReviewQueueService
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


def _s(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _build_actions(item: dict[str, Any]) -> list[ReviewDetailAction]:
    actions: list[ReviewDetailAction] = []
    status = _s(item.get("status")) or "pending"
    review_id = _s(item.get("review_id")) or _s(item.get("id")) or ""

    if status == "pending":
        actions.append(
            ReviewDetailAction(
                key="assign",
                label="Assign to analyst",
                api_path=f"/api/review-queue/{review_id}/assign",
                body={"reviewer_id": "analyst-1"},
                style="primary",
            )
        )

    if status == "in_review":
        actions.append(
            ReviewDetailAction(
                key="complete",
                label="Complete review",
                api_path=f"/api/review-queue/{review_id}/complete",
                body={},
                style="success",
            )
        )
        actions.append(
            ReviewDetailAction(
                key="dismiss",
                label="Dismiss review",
                api_path=f"/api/review-queue/{review_id}/dismiss",
                body={"reason": "dismissed-by-analyst"},
                style="danger",
            )
        )

    if status in {"completed", "dismissed", "rejected"}:
        actions.append(
            ReviewDetailAction(
                key="reopen",
                label="Reopen review",
                api_path=f"/api/review-queue/{review_id}/reopen",
                body={},
                style="default",
            )
        )

    return actions


def _build_fields(item: dict[str, Any]) -> list[ReviewDetailField]:
    def _f(key: str, label: str) -> ReviewDetailField:
        return ReviewDetailField(key=key, label=label, value=_s(item.get(key)))

    return [
        _f("review_id", "Review ID"),
        _f("source", "Source"),
        _f("incident_id", "Incident ID"),
        _f("quarantine_id", "Quarantine ID"),
        _f("priority", "Priority"),
        _f("status", "Status"),
        _f("assigned_to", "Assigned To"),
        _f("created_at", "Created At"),
        _f("updated_at", "Updated At"),
        _f("verdict", "Verdict"),
    ]


@router.get(
    "/{review_id}",
    response_model=ReviewDetailResponse,
    summary="Get review detail",
)
def get_review_detail(review_id: str) -> ReviewDetailResponse:
    normalized = review_id.strip()
    if not normalized:
        raise HTTPException(status_code=404, detail="review item not found")

    service: ReviewQueueService = get_review_queue_service()
    item = service.get(normalized)

    if item is None:
        raise HTTPException(
            status_code=404,
            detail=f"review item not found: {normalized}",
        )

    evidence_raw = item.get("evidence") or []
    evidence_items = [
        ReviewEvidenceItem(
            index=idx + 1,
            data=ev if isinstance(ev, dict) else {"value": ev},
        )
        for idx, ev in enumerate(evidence_raw)
    ]

    reasons_raw = item.get("reasons") or item.get("tags") or []
    reasons = [str(r) for r in reasons_raw if r is not None]

    return ReviewDetailResponse(
        review_id=_s(item.get("review_id")) or _s(item.get("id")) or normalized,
        title=_s(item.get("title")) or "Review",
        summary=_s(item.get("summary")) or "",
        status=_s(item.get("status")) or "pending",
        priority=_s(item.get("priority")) or "medium",
        source=_s(item.get("source")) or "ironclaw",
        source_id=_s(item.get("incident_id")) or _s(item.get("quarantine_id")) or _s(item.get("review_id")) or normalized,
        assigned_to=_s(item.get("assigned_to")),
        created_at=_s(item.get("created_at")) or "",
        updated_at=_s(item.get("updated_at")) or "",
        completed_at=_s(item.get("completed_at")),
        fields=_build_fields(item),
        reasons=reasons,
        evidence=evidence_items,
        actions=_build_actions(item),
    )
