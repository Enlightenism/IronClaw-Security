from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4


class ReviewStatus(str, Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ReviewPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class ReviewEvidence:
    kind: str
    value: Any
    label: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "label": self.label,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ReviewComment:
    comment_id: str
    author_id: str
    message: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "comment_id": self.comment_id,
            "author_id": self.author_id,
            "message": self.message,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ReviewDecision:
    reviewer_id: str
    verdict: str
    reason: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reviewer_id": self.reviewer_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ReviewItem:
    review_id: str
    request_id: str
    execution_id: str | None
    title: str
    summary: str
    status: ReviewStatus = ReviewStatus.PENDING
    priority: ReviewPriority = ReviewPriority.MEDIUM
    queue: str = "default"
    assigned_to: str | None = None
    created_by: str | None = None
    due_at: str | None = None
    escalation_at: str | None = None
    tags: list[str] = field(default_factory=list)
    evidence: list[ReviewEvidence] = field(default_factory=list)
    comments: list[ReviewComment] = field(default_factory=list)
    decisions: list[ReviewDecision] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def touch(self) -> None:
        self.updated_at = datetime.now(UTC).isoformat()

    def add_comment(self, author_id: str, message: str, metadata: Mapping[str, Any] | None = None) -> ReviewComment:
        comment = ReviewComment(
            comment_id=f"cmt-{uuid4().hex}",
            author_id=author_id,
            message=message,
            metadata=dict(metadata or {}),
        )
        self.comments.append(comment)
        self.touch()
        return comment

    def add_decision(self, reviewer_id: str, verdict: str, reason: str, metadata: Mapping[str, Any] | None = None) -> ReviewDecision:
        decision = ReviewDecision(
            reviewer_id=reviewer_id,
            verdict=verdict,
            reason=reason,
            metadata=dict(metadata or {}),
        )
        self.decisions.append(decision)
        self.touch()
        return decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "request_id": self.request_id,
            "execution_id": self.execution_id,
            "title": self.title,
            "summary": self.summary,
            "status": self.status.value,
            "priority": self.priority.value,
            "queue": self.queue,
            "assigned_to": self.assigned_to,
            "created_by": self.created_by,
            "due_at": self.due_at,
            "escalation_at": self.escalation_at,
            "tags": list(self.tags),
            "evidence": [item.to_dict() for item in self.evidence],
            "comments": [item.to_dict() for item in self.comments],
            "decisions": [item.to_dict() for item in self.decisions],
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ReviewQueue:
    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self._items: dict[str, ReviewItem] = {}
        self.clock = clock or (lambda: datetime.now(UTC))
        self.sink = sink

    def create(
        self,
        *,
        request_id: str,
        title: str,
        summary: str,
        execution_id: str | None = None,
        priority: ReviewPriority | str = ReviewPriority.MEDIUM,
        queue: str = "default",
        created_by: str | None = None,
        due_in_minutes: int | None = 60,
        escalate_in_minutes: int | None = 30,
        tags: Iterable[str] | None = None,
        evidence: Iterable[ReviewEvidence | Mapping[str, Any]] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ReviewItem:
        item = ReviewItem(
            review_id=f"rev-{uuid4().hex}",
            request_id=request_id,
            execution_id=execution_id,
            title=title,
            summary=summary,
            priority=self._normalize_priority(priority),
            queue=queue,
            created_by=created_by,
            due_at=self._future_iso(due_in_minutes),
            escalation_at=self._future_iso(escalate_in_minutes),
            tags=[str(tag) for tag in (tags or [])],
            evidence=[self._normalize_evidence(ev) for ev in (evidence or [])],
            metadata=dict(metadata or {}),
        )
        self._items[item.review_id] = item
        self._emit("review.created", item)
        return item

    def get(self, review_id: str) -> ReviewItem | None:
        return self._items.get(review_id)

    def list(
        self,
        *,
        status: ReviewStatus | str | None = None,
        queue: str | None = None,
        assigned_to: str | None = None,
        priority: ReviewPriority | str | None = None,
    ) -> list[ReviewItem]:
        items = list(self._items.values())

        if status is not None:
            status_value = self._normalize_status(status).value
            items = [item for item in items if item.status.value == status_value]

        if queue is not None:
            items = [item for item in items if item.queue == queue]

        if assigned_to is not None:
            items = [item for item in items if item.assigned_to == assigned_to]

        if priority is not None:
            priority_value = self._normalize_priority(priority).value
            items = [item for item in items if item.priority.value == priority_value]

        return sorted(items, key=self._sort_key)

    def assign(self, review_id: str, reviewer_id: str, *, actor_id: str | None = None) -> ReviewItem:
        item = self._require(review_id)
        item.assigned_to = reviewer_id
        item.status = ReviewStatus.ASSIGNED if item.status == ReviewStatus.PENDING else item.status
        item.touch()
        item.add_comment(
            author_id=actor_id or reviewer_id,
            message=f"Assigned to reviewer {reviewer_id}.",
            metadata={"event": "assigned"},
        )
        self._emit("review.assigned", item)
        return item

    def start(self, review_id: str, reviewer_id: str) -> ReviewItem:
        item = self._require(review_id)
        item.assigned_to = reviewer_id
        item.status = ReviewStatus.IN_REVIEW
        item.touch()
        item.add_comment(
            author_id=reviewer_id,
            message="Review started.",
            metadata={"event": "in_review"},
        )
        self._emit("review.started", item)
        return item

    def approve(self, review_id: str, reviewer_id: str, reason: str, *, metadata: Mapping[str, Any] | None = None) -> ReviewItem:
        item = self._require(review_id)
        item.status = ReviewStatus.APPROVED
        item.assigned_to = reviewer_id
        item.add_decision(reviewer_id, "approved", reason, metadata)
        self._emit("review.approved", item)
        return item

    def reject(self, review_id: str, reviewer_id: str, reason: str, *, metadata: Mapping[str, Any] | None = None) -> ReviewItem:
        item = self._require(review_id)
        item.status = ReviewStatus.REJECTED
        item.assigned_to = reviewer_id
        item.add_decision(reviewer_id, "rejected", reason, metadata)
        self._emit("review.rejected", item)
        return item

    def escalate(self, review_id: str, *, actor_id: str, reason: str, queue: str | None = None) -> ReviewItem:
        item = self._require(review_id)
        item.status = ReviewStatus.ESCALATED
        if queue:
            item.queue = queue
        item.add_comment(
            author_id=actor_id,
            message=reason,
            metadata={"event": "escalated", "queue": item.queue},
        )
        self._emit("review.escalated", item)
        return item

    def cancel(self, review_id: str, *, actor_id: str, reason: str) -> ReviewItem:
        item = self._require(review_id)
        item.status = ReviewStatus.CANCELLED
        item.add_comment(
            author_id=actor_id,
            message=reason,
            metadata={"event": "cancelled"},
        )
        self._emit("review.cancelled", item)
        return item

    def add_comment(
        self,
        review_id: str,
        *,
        author_id: str,
        message: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> ReviewComment:
        item = self._require(review_id)
        comment = item.add_comment(author_id, message, metadata)
        self._emit("review.comment_added", item)
        return comment

    def add_evidence(
        self,
        review_id: str,
        evidence: ReviewEvidence | Mapping[str, Any],
    ) -> ReviewItem:
        item = self._require(review_id)
        item.evidence.append(self._normalize_evidence(evidence))
        item.touch()
        self._emit("review.evidence_added", item)
        return item

    def expire_due_items(self) -> list[ReviewItem]:
        now = self.clock()
        expired: list[ReviewItem] = []
        for item in self._items.values():
            if item.status in {
                ReviewStatus.APPROVED,
                ReviewStatus.REJECTED,
                ReviewStatus.CANCELLED,
                ReviewStatus.EXPIRED,
            }:
                continue
            if item.due_at and datetime.fromisoformat(item.due_at) <= now:
                item.status = ReviewStatus.EXPIRED
                item.touch()
                expired.append(item)
                self._emit("review.expired", item)
        return expired

    def auto_escalate(self) -> list[ReviewItem]:
        now = self.clock()
        escalated: list[ReviewItem] = []
        for item in self._items.values():
            if item.status not in {
                ReviewStatus.PENDING,
                ReviewStatus.ASSIGNED,
                ReviewStatus.IN_REVIEW,
            }:
                continue
            if item.escalation_at and datetime.fromisoformat(item.escalation_at) <= now:
                item.status = ReviewStatus.ESCALATED
                item.touch()
                item.add_comment(
                    author_id="system",
                    message="Automatically escalated after SLA threshold.",
                    metadata={"event": "auto_escalated"},
                )
                escalated.append(item)
                self._emit("review.auto_escalated", item)
        return escalated

    def stats(self) -> dict[str, Any]:
        counts_by_status: dict[str, int] = {}
        counts_by_priority: dict[str, int] = {}

        for item in self._items.values():
            counts_by_status[item.status.value] = counts_by_status.get(item.status.value, 0) + 1
            counts_by_priority[item.priority.value] = counts_by_priority.get(item.priority.value, 0) + 1

        return {
            "total": len(self._items),
            "by_status": counts_by_status,
            "by_priority": counts_by_priority,
            "open": sum(
                1
                for item in self._items.values()
                if item.status
                in {
                    ReviewStatus.PENDING,
                    ReviewStatus.ASSIGNED,
                    ReviewStatus.IN_REVIEW,
                    ReviewStatus.ESCALATED,
                }
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.list()],
            "stats": self.stats(),
        }

    def _require(self, review_id: str) -> ReviewItem:
        item = self.get(review_id)
        if item is None:
            raise KeyError(f"Review item not found: {review_id}")
        return item

    def _normalize_priority(self, value: ReviewPriority | str) -> ReviewPriority:
        if isinstance(value, ReviewPriority):
            return value
        return ReviewPriority(str(value).lower())

    def _normalize_status(self, value: ReviewStatus | str) -> ReviewStatus:
        if isinstance(value, ReviewStatus):
            return value
        return ReviewStatus(str(value).lower())

    def _normalize_evidence(self, value: ReviewEvidence | Mapping[str, Any]) -> ReviewEvidence:
        if isinstance(value, ReviewEvidence):
            return value
        payload = dict(value)
        return ReviewEvidence(
            kind=str(payload.get("kind", "unknown")),
            value=payload.get("value"),
            label=payload.get("label"),
            metadata=dict(payload.get("metadata") or {}),
        )

    def _future_iso(self, minutes: int | None) -> str | None:
        if minutes is None:
            return None
        return (self.clock() + timedelta(minutes=minutes)).isoformat()

    def _sort_key(self, item: ReviewItem) -> tuple[int, str, str]:
        priority_rank = {
            ReviewPriority.CRITICAL.value: 0,
            ReviewPriority.HIGH.value: 1,
            ReviewPriority.MEDIUM.value: 2,
            ReviewPriority.LOW.value: 3,
        }
        return (
            priority_rank.get(item.priority.value, 99),
            item.due_at or "",
            item.created_at,
        )

    def _emit(self, event: str, item: ReviewItem) -> None:
        if self.sink is not None:
            self.sink(
                {
                    "event": event,
                    "review": item.to_dict(),
                    "timestamp": self.clock().isoformat(),
                }
            )


def build_review_item(
    *,
    request_id: str,
    title: str,
    summary: str,
    execution_id: str | None = None,
    priority: ReviewPriority | str = ReviewPriority.MEDIUM,
    queue: str = "default",
    created_by: str | None = None,
    due_in_minutes: int | None = 60,
    escalate_in_minutes: int | None = 30,
    tags: Iterable[str] | None = None,
    evidence: Iterable[ReviewEvidence | Mapping[str, Any]] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ReviewItem:
    queue_obj = ReviewQueue()
    return queue_obj.create(
        request_id=request_id,
        title=title,
        summary=summary,
        execution_id=execution_id,
        priority=priority,
        queue=queue,
        created_by=created_by,
        due_in_minutes=due_in_minutes,
        escalate_in_minutes=escalate_in_minutes,
        tags=tags,
        evidence=evidence,
        metadata=metadata,
    )


__all__ = [
    "ReviewComment",
    "ReviewDecision",
    "ReviewEvidence",
    "ReviewItem",
    "ReviewPriority",
    "ReviewQueue",
    "ReviewStatus",
    "build_review_item",
]