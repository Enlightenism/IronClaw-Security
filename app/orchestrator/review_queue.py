from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

ReviewStatus = Literal["pending", "approved", "rejected"]
ReviewPriority = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class ReviewItem:
    review_id: str
    actor_id: str
    action_type: str
    target: str
    verdict: str
    risk_score: int
    priority: ReviewPriority
    reason: str
    status: ReviewStatus = "pending"
    file_path: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    reviewed_at: str | None = None
    reviewed_by: str | None = None
    review_note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewQueue:
    items: list[ReviewItem] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.items],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def initialize_review_queue() -> ReviewQueue:
    return ReviewQueue()


def create_review_item(
    *,
    actor_id: str,
    action_type: str,
    target: str,
    verdict: str,
    risk_score: int,
    reason: str,
    file_path: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ReviewItem:
    return ReviewItem(
        review_id=_build_review_id(),
        actor_id=actor_id,
        action_type=action_type,
        target=target,
        verdict=verdict,
        risk_score=risk_score,
        priority=_priority_from_risk_score(risk_score),
        reason=reason,
        file_path=file_path,
        session_id=session_id,
        metadata=metadata or {},
    )


def enqueue_review_item(queue: ReviewQueue, item: ReviewItem) -> ReviewQueue:
    return ReviewQueue(
        items=[*queue.items, item],
        created_at=queue.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )


def get_review_item(queue: ReviewQueue, review_id: str) -> ReviewItem | None:
    for item in queue.items:
        if item.review_id == review_id:
            return item
    return None


def list_pending_review_items(queue: ReviewQueue) -> list[ReviewItem]:
    return [item for item in queue.items if item.status == "pending"]


def approve_review_item(
    queue: ReviewQueue,
    *,
    review_id: str,
    reviewed_by: str,
    review_note: str | None = None,
) -> ReviewQueue:
    return _update_review_status(
        queue,
        review_id=review_id,
        status="approved",
        reviewed_by=reviewed_by,
        review_note=review_note,
    )


def reject_review_item(
    queue: ReviewQueue,
    *,
    review_id: str,
    reviewed_by: str,
    review_note: str | None = None,
) -> ReviewQueue:
    return _update_review_status(
        queue,
        review_id=review_id,
        status="rejected",
        reviewed_by=reviewed_by,
        review_note=review_note,
    )


def summarize_review_queue(queue: ReviewQueue) -> dict[str, Any]:
    return {
        "total_items": len(queue.items),
        "pending_items": sum(1 for item in queue.items if item.status == "pending"),
        "approved_items": sum(1 for item in queue.items if item.status == "approved"),
        "rejected_items": sum(1 for item in queue.items if item.status == "rejected"),
        "critical_items": sum(1 for item in queue.items if item.priority == "critical"),
        "high_items": sum(1 for item in queue.items if item.priority == "high"),
        "medium_items": sum(1 for item in queue.items if item.priority == "medium"),
        "low_items": sum(1 for item in queue.items if item.priority == "low"),
        "updated_at": queue.updated_at,
    }


def _update_review_status(
    queue: ReviewQueue,
    *,
    review_id: str,
    status: ReviewStatus,
    reviewed_by: str,
    review_note: str | None,
) -> ReviewQueue:
    found = False
    updated_items: list[ReviewItem] = []

    for item in queue.items:
        if item.review_id != review_id:
            updated_items.append(item)
            continue

        found = True
        updated_items.append(
            ReviewItem(
                review_id=item.review_id,
                actor_id=item.actor_id,
                action_type=item.action_type,
                target=item.target,
                verdict=item.verdict,
                risk_score=item.risk_score,
                priority=item.priority,
                reason=item.reason,
                status=status,
                file_path=item.file_path,
                session_id=item.session_id,
                metadata=item.metadata,
                created_at=item.created_at,
                reviewed_at=datetime.now(UTC).isoformat(),
                reviewed_by=reviewed_by,
                review_note=review_note,
            ),
        )

    if not found:
        raise ValueError(f"Review item not found: {review_id}")

    return ReviewQueue(
        items=updated_items,
        created_at=queue.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )


def _priority_from_risk_score(risk_score: int) -> ReviewPriority:
    if risk_score >= 90:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"


def _build_review_id() -> str:
    now = datetime.now(UTC)
    return f"review-{now.strftime('%Y%m%d%H%M%S%f')}"


if __name__ == "__main__":
    queue = initialize_review_queue()

    item = create_review_item(
        actor_id="agent-security-01",
        action_type="tool_call",
        target="shell",
        verdict="block",
        risk_score=88,
        reason="Risky shell operation requires human review.",
        file_path="app/orchestrator/policy_enforcer.py",
        session_id="sess-001",
        metadata={"source": "policy_enforcer"},
    )

    queue = enqueue_review_item(queue, item)
    queue = approve_review_item(
        queue,
        review_id=item.review_id,
        reviewed_by="human-admin",
        review_note="Approved after manual inspection.",
    )

    import json

    print(json.dumps(summarize_review_queue(queue), ensure_ascii=False, indent=2))
