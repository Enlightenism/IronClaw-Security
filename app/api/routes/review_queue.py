from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key


router = APIRouter(
    prefix="/guard/reviews",
    tags=["review-queue"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class ReviewReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int | None = None


class ReviewActionRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=120)
    notes: str | None = Field(default=None, max_length=2000)


class ReviewItemResponse(BaseModel):
    review_id: str
    status: str
    action_type: str
    target: str
    risk_score: int
    created_at: str
    updated_at: str
    requested_by: str | None = None
    session_id: str | None = None
    actor_id: str | None = None
    policy_verdict: str
    recommended_action: str
    final_action: str | None = None
    reason: str
    reasons: list[ReviewReasonView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReviewQueueSummaryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    pending: int
    approved: int
    rejected: int


_SAMPLE_REVIEWS: list[dict[str, Any]] = [
    {
        "review_id": "review_001",
        "status": "pending",
        "action_type": "shell_execute",
        "target": "rm -rf /workspace",
        "risk_score": 97,
        "created_at": _utc_now_iso(),
        "updated_at": _utc_now_iso(),
        "requested_by": "client-alpha",
        "session_id": "sess-001",
        "actor_id": "actor-001",
        "policy_verdict": "block",
        "recommended_action": "reject",
        "final_action": None,
        "reason": "Destructive shell command requires manual review.",
        "reasons": [
            {
                "source": "policy",
                "label": "Destructive command",
                "details": "The request attempts to remove a workspace path recursively.",
                "score": 97,
            }
        ],
        "metadata": {"filepath": "/workspace"},
    },
    {
        "review_id": "review_002",
        "status": "pending",
        "action_type": "http_fetch",
        "target": "https://unknown.example/payload",
        "risk_score": 72,
        "created_at": _utc_now_iso(),
        "updated_at": _utc_now_iso(),
        "requested_by": "client-beta",
        "session_id": "sess-002",
        "actor_id": "actor-002",
        "policy_verdict": "review",
        "recommended_action": "approve",
        "final_action": None,
        "reason": "External content source should be reviewed before release.",
        "reasons": [
            {
                "source": "scan",
                "label": "Untrusted source",
                "details": "The destination is unknown and returned suspicious content indicators.",
                "score": 72,
            }
        ],
        "metadata": {"url": "https://unknown.example/payload"},
    },
]


def _to_review_item(record: dict[str, Any]) -> ReviewItemResponse:
    return ReviewItemResponse(
        review_id=str(record["review_id"]),
        status=str(record["status"]),
        action_type=str(record["action_type"]),
        target=str(record["target"]),
        risk_score=int(record["risk_score"]),
        created_at=str(record["created_at"]),
        updated_at=str(record["updated_at"]),
        requested_by=record.get("requested_by"),
        session_id=record.get("session_id"),
        actor_id=record.get("actor_id"),
        policy_verdict=str(record["policy_verdict"]),
        recommended_action=str(record["recommended_action"]),
        final_action=record.get("final_action"),
        reason=str(record["reason"]),
        reasons=[
            ReviewReasonView(
                source=str(item["source"]),
                label=str(item["label"]),
                details=str(item["details"]),
                score=item.get("score"),
            )
            for item in record.get("reasons", [])
        ],
        metadata=dict(record.get("metadata", {})),
    )


def _find_review(review_id: str) -> dict[str, Any] | None:
    for record in _SAMPLE_REVIEWS:
        if record["review_id"] == review_id:
            return record
    return None


@router.get("/summary", response_model=ReviewQueueSummaryResponse)
def get_review_summary() -> ReviewQueueSummaryResponse:
    total = len(_SAMPLE_REVIEWS)
    pending = sum(1 for item in _SAMPLE_REVIEWS if item["status"] == "pending")
    approved = sum(1 for item in _SAMPLE_REVIEWS if item["status"] == "approved")
    rejected = sum(1 for item in _SAMPLE_REVIEWS if item["status"] == "rejected")

    return ReviewQueueSummaryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=total,
        pending=pending,
        approved=approved,
        rejected=rejected,
    )


@router.get("", response_model=list[ReviewItemResponse])
def get_all_reviews(
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ReviewItemResponse]:
    return [_to_review_item(record) for record in _SAMPLE_REVIEWS[:limit]]


@router.get("/pending", response_model=list[ReviewItemResponse])
def get_pending_reviews(
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ReviewItemResponse]:
    pending_items = [record for record in _SAMPLE_REVIEWS if record["status"] == "pending"]
    return [_to_review_item(record) for record in pending_items[:limit]]


@router.get("/{review_id}", response_model=ReviewItemResponse)
def get_review(review_id: str) -> ReviewItemResponse:
    record = _find_review(review_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown review item: {review_id}",
        )
    return _to_review_item(record)


@router.post("/{review_id}/approve", response_model=ReviewItemResponse)
def approve_review_item(
    review_id: str,
    payload: ReviewActionRequest,
) -> ReviewItemResponse:
    record = _find_review(review_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown review item: {review_id}",
        )

    record["status"] = "approved"
    record["final_action"] = "approve"
    record["updated_at"] = _utc_now_iso()
    record["metadata"] = {
        **dict(record.get("metadata", {})),
        "reviewer": payload.reviewer,
        "review_notes": payload.notes,
    }
    return _to_review_item(record)


@router.post("/{review_id}/reject", response_model=ReviewItemResponse)
def reject_review_item(
    review_id: str,
    payload: ReviewActionRequest,
) -> ReviewItemResponse:
    record = _find_review(review_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown review item: {review_id}",
        )

    record["status"] = "rejected"
    record["final_action"] = "reject"
    record["updated_at"] = _utc_now_iso()
    record["metadata"] = {
        **dict(record.get("metadata", {})),
        "reviewer": payload.reviewer,
        "review_notes": payload.notes,
    }
    return _to_review_item(record)