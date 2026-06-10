from __future__ import annotations

from typing import Any

from app.orchestrator.review_queue import (
    ReviewItem,
    ReviewQueue,
    approve_review_item,
    get_review_item,
    initialize_review_queue,
    list_pending_review_items,
    reject_review_item,
    summarize_review_queue,
)

_active_review_queue: ReviewQueue | None = None


def get_review_queue() -> ReviewQueue:
    global _active_review_queue
    if _active_review_queue is None:
        _active_review_queue = initialize_review_queue()
    return _active_review_queue


def set_review_queue(queue: ReviewQueue) -> ReviewQueue:
    global _active_review_queue
    _active_review_queue = queue
    return _active_review_queue


def reset_review_queue() -> ReviewQueue:
    global _active_review_queue
    _active_review_queue = initialize_review_queue()
    return _active_review_queue


def get_review_queue_summary() -> dict[str, Any]:
    queue = get_review_queue()
    return summarize_review_queue(queue)


def list_pending_reviews() -> list[dict[str, Any]]:
    queue = get_review_queue()
    items = list_pending_review_items(queue)
    return [item.to_dict() for item in items]


def list_all_reviews() -> list[dict[str, Any]]:
    queue = get_review_queue()
    return [item.to_dict() for item in queue.items]


def get_review_by_id(review_id: str) -> dict[str, Any] | None:
    queue = get_review_queue()
    item = get_review_item(queue, review_id)
    if item is None:
        return None
    return item.to_dict()


def approve_review(
    *,
    review_id: str,
    reviewed_by: str,
    review_note: str | None = None,
) -> dict[str, Any]:
    queue = get_review_queue()
    updated_queue = approve_review_item(
        queue,
        review_id=review_id,
        reviewed_by=reviewed_by,
        review_note=review_note,
    )
    set_review_queue(updated_queue)
    item = get_review_item(updated_queue, review_id)
    if item is None:
        raise ValueError(f"Review item not found after approval: {review_id}")
    return item.to_dict()


def reject_review(
    *,
    review_id: str,
    reviewed_by: str,
    review_note: str | None = None,
) -> dict[str, Any]:
    queue = get_review_queue()
    updated_queue = reject_review_item(
        queue,
        review_id=review_id,
        reviewed_by=reviewed_by,
        review_note=review_note,
    )
    set_review_queue(updated_queue)
    item = get_review_item(updated_queue, review_id)
    if item is None:
        raise ValueError(f"Review item not found after rejection: {review_id}")
    return item.to_dict()


def import_review_queue(queue: ReviewQueue) -> ReviewQueue:
    return set_review_queue(queue)


def export_review_queue() -> ReviewQueue:
    return get_review_queue()


def has_pending_reviews() -> bool:
    queue = get_review_queue()
    return any(item.status == "pending" for item in queue.items)


def count_pending_reviews() -> int:
    queue = get_review_queue()
    return sum(1 for item in queue.items if item.status == "pending")


def count_reviews_by_status() -> dict[str, int]:
    queue = get_review_queue()
    counts = {
        "pending": 0,
        "approved": 0,
        "rejected": 0,
    }
    for item in queue.items:
        counts[item.status] += 1
    return counts


def count_reviews_by_priority() -> dict[str, int]:
    queue = get_review_queue()
    counts = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    for item in queue.items:
        counts[item.priority] += 1
    return counts


def _coerce_review_item(item: ReviewItem | dict[str, Any]) -> dict[str, Any]:
    if hasattr(item, "to_dict"):
        return item.to_dict()
    return {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v) for k, v in dict(item).items()}
