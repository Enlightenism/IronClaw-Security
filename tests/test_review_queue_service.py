from __future__ import annotations

from app.orchestrator.review_queue import (
    create_review_item,
    enqueue_review_item,
    initialize_review_queue,
)
from app.services.review_queue_service import (
    approve_review,
    count_pending_reviews,
    count_reviews_by_priority,
    count_reviews_by_status,
    get_review_by_id,
    get_review_queue_summary,
    has_pending_reviews,
    import_review_queue,
    list_all_reviews,
    list_pending_reviews,
    reject_review,
    reset_review_queue,
)


def _seed_review_queue() -> tuple[str, str]:
    queue = initialize_review_queue()

    item_one = create_review_item(
        actor_id="agent-review-001",
        action_type="tool_call",
        target="shell",
        verdict="quarantine",
        risk_score=92,
        reason="High-risk shell command requires review.",
        file_path="app/orchestrator/policy_enforcer.py",
        session_id="review-session-001",
        metadata={"source": "test_seed"},
    )
    item_two = create_review_item(
        actor_id="agent-review-002",
        action_type="http_fetch",
        target="https://example.com",
        verdict="warn",
        risk_score=45,
        reason="Moderate-risk fetch should be reviewed.",
        file_path="app/api/action_execute.py",
        session_id="review-session-002",
        metadata={"source": "test_seed"},
    )

    queue = enqueue_review_item(queue, item_one)
    queue = enqueue_review_item(queue, item_two)
    import_review_queue(queue)

    return item_one.review_id, item_two.review_id


def setup_function() -> None:
    reset_review_queue()


def test_review_queue_service_summary_empty():
    summary = get_review_queue_summary()

    assert summary["total_items"] == 0
    assert summary["pending_items"] == 0
    assert summary["approved_items"] == 0
    assert summary["rejected_items"] == 0


def test_list_and_get_reviews():
    review_id_one, review_id_two = _seed_review_queue()

    all_reviews = list_all_reviews()
    pending_reviews = list_pending_reviews()
    first_review = get_review_by_id(review_id_one)
    second_review = get_review_by_id(review_id_two)

    assert len(all_reviews) == 2
    assert len(pending_reviews) == 2
    assert first_review is not None
    assert second_review is not None
    assert first_review["review_id"] == review_id_one
    assert second_review["review_id"] == review_id_two


def test_approve_review_updates_status():
    review_id_one, _ = _seed_review_queue()

    approved = approve_review(
        review_id=review_id_one,
        reviewed_by="human-admin",
        review_note="Approved after manual inspection.",
    )

    assert approved["review_id"] == review_id_one
    assert approved["status"] == "approved"
    assert approved["reviewed_by"] == "human-admin"
    assert approved["review_note"] == "Approved after manual inspection."

    fetched = get_review_by_id(review_id_one)
    assert fetched is not None
    assert fetched["status"] == "approved"


def test_reject_review_updates_status():
    _, review_id_two = _seed_review_queue()

    rejected = reject_review(
        review_id=review_id_two,
        reviewed_by="human-admin",
        review_note="Rejected due to unsafe target.",
    )

    assert rejected["review_id"] == review_id_two
    assert rejected["status"] == "rejected"
    assert rejected["reviewed_by"] == "human-admin"
    assert rejected["review_note"] == "Rejected due to unsafe target."

    fetched = get_review_by_id(review_id_two)
    assert fetched is not None
    assert fetched["status"] == "rejected"


def test_pending_and_counts():
    review_id_one, _ = _seed_review_queue()

    assert has_pending_reviews() is True
    assert count_pending_reviews() == 2

    approve_review(
        review_id=review_id_one,
        reviewed_by="human-admin",
        review_note="Approved after manual inspection.",
    )

    status_counts = count_reviews_by_status()
    priority_counts = count_reviews_by_priority()

    assert status_counts["approved"] == 1
    assert status_counts["pending"] == 1
    assert status_counts["rejected"] == 0

    assert priority_counts["critical"] == 1
    assert priority_counts["medium"] == 1
    assert priority_counts["high"] == 0
    assert priority_counts["low"] == 0


def test_approve_missing_review_raises_value_error():
    reset_review_queue()

    try:
        approve_review(
            review_id="missing-review-id",
            reviewed_by="human-admin",
        )
    except ValueError as exc:
        assert "missing-review-id" in str(exc)
    else:
        raise AssertionError("Expected ValueError for missing review id")


def test_reject_missing_review_raises_value_error():
    reset_review_queue()

    try:
        reject_review(
            review_id="missing-review-id",
            reviewed_by="human-admin",
        )
    except ValueError as exc:
        assert "missing-review-id" in str(exc)
    else:
        raise AssertionError("Expected ValueError for missing review id")