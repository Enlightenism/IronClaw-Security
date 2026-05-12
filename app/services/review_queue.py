from __future__ import annotations

from typing import Any

from app.models.review_queue import ReviewActionRequest
from app.services.review_queue_service import (
    approve_review,
    get_review_queue_summary,
    list_all_reviews,
    list_pending_reviews,
    reject_review,
)
from app.services.review_queue_service import (
    get_review_by_id as _get_review_by_id,
)


def get_review_summary() -> dict[str, Any]:
    return get_review_queue_summary()


def get_all_reviews() -> list[dict[str, Any]]:
    return list_all_reviews()


def get_pending_reviews() -> list[dict[str, Any]]:
    return list_pending_reviews()


def get_review_by_id(review_id: str) -> dict[str, Any] | None:
    return _get_review_by_id(review_id)


def approve_review_item(
    review_id: str,
    payload: ReviewActionRequest,
) -> dict[str, Any] | None:
    try:
        return approve_review(
            review_id=review_id,
            reviewed_by=payload.actor or "api",
            review_note=payload.note,
        )
    except ValueError:
        return None


def reject_review_item(
    review_id: str,
    payload: ReviewActionRequest,
) -> dict[str, Any] | None:
    try:
        return reject_review(
            review_id=review_id,
            reviewed_by=payload.actor or "api",
            review_note=payload.note,
        )
    except ValueError:
        return None