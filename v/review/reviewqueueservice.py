from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Deque, Dict, List, Optional

from pydantic import BaseModel, Field


class ReviewPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    DISMISSED = "dismissed"


class ReviewSource(str, Enum):
    INCIDENT = "incident"
    SESSION = "session"
    SIGNAL = "signal"
    ARTIFACT = "artifact"
    MANUAL = "manual"


class ReviewQueueItem(BaseModel):
    review_id: str = Field(..., description="Stable review queue identifier")
    source: ReviewSource = Field(..., description="Origin type for this review item")
    source_id: str = Field(..., description="Stable ID of the queued entity")
    priority: ReviewPriority = Field(..., description="Queue priority")
    status: ReviewStatus = Field(default=ReviewStatus.PENDING, description="Queue state")
    title: str = Field(..., description="Human-readable review title")
    summary: str = Field(..., description="Short analyst-facing summary")
    reasons: List[str] = Field(default_factory=list, description="Escalation reasons")
    evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Compact evidence objects for analyst context",
    )
    assigned_to: Optional[str] = Field(
        default=None,
        description="Reviewer currently assigned to this queue item",
    )
    created_at: str = Field(..., description="UTC ISO-8601 creation timestamp")
    updated_at: str = Field(..., description="UTC ISO-8601 update timestamp")
    completed_at: Optional[str] = Field(
        default=None,
        description="UTC ISO-8601 completion timestamp",
    )


class ReviewQueueService:
    """
    In-memory analyst review queue with deterministic escalation behavior.

    Goals:
    - Fast drop-in service for orchestration/testing.
    - Deduplicate by (source, source_id) so repeated escalations update instead of fan out.
    - Preserve analyst-readable context and evidence.
    - Keep API simple for later database-backed replacement.
    """

    def __init__(self) -> None:
        self._items: Dict[str, ReviewQueueItem] = {}
        self._index_by_source: Dict[tuple[str, str], str] = {}
        self._pending_order: Deque[str] = deque()
        self._counter = 1
        self._lock = Lock()

    def list_items(
        self,
        *,
        status: Optional[ReviewStatus] = None,
        assigned_to: Optional[str] = None,
    ) -> List[ReviewQueueItem]:
        items = list(self._items.values())
        if status is not None:
            items = [item for item in items if item.status == status]
        if assigned_to is not None:
            items = [item for item in items if item.assigned_to == assigned_to]
        return sorted(items, key=self._sort_key)

    def get(self, review_id: str) -> Optional[ReviewQueueItem]:
        return self._items.get(review_id)

    def enqueue(
        self,
        *,
        source: ReviewSource,
        source_id: str,
        priority: ReviewPriority,
        title: str,
        summary: str,
        reasons: Optional[List[str]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
    ) -> ReviewQueueItem:
        with self._lock:
            key = (source.value, source_id)
            existing_id = self._index_by_source.get(key)
            if existing_id:
                return self._update_existing(
                    review_id=existing_id,
                    priority=priority,
                    title=title,
                    summary=summary,
                    reasons=reasons or [],
                    evidence=evidence or [],
                )

            now = self._utcnow()
            review_id = self._next_review_id()
            item = ReviewQueueItem(
                review_id=review_id,
                source=source,
                source_id=source_id,
                priority=priority,
                title=title,
                summary=summary,
                reasons=self._dedupe_strings(reasons or []),
                evidence=self._dedupe_evidence(evidence or []),
                created_at=now,
                updated_at=now,
            )
            self._items[review_id] = item
            self._index_by_source[key] = review_id
            self._push_pending(review_id)
            return item

    def escalate_incident(
        self,
        *,
        incident_id: str,
        priority: str,
        title: str,
        summary: str,
        reasons: Optional[List[str]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
    ) -> ReviewQueueItem:
        return self.enqueue(
            source=ReviewSource.INCIDENT,
            source_id=incident_id,
            priority=self._coerce_priority(priority),
            title=title,
            summary=summary,
            reasons=reasons,
            evidence=evidence,
        )

    def escalate_session(
        self,
        *,
        session_id: str,
        priority: str,
        title: str,
        summary: str,
        reasons: Optional[List[str]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
    ) -> ReviewQueueItem:
        return self.enqueue(
            source=ReviewSource.SESSION,
            source_id=session_id,
            priority=self._coerce_priority(priority),
            title=title,
            summary=summary,
            reasons=reasons,
            evidence=evidence,
        )

    def claim_next(self, reviewer_id: str) -> Optional[ReviewQueueItem]:
        with self._lock:
            self._rebuild_pending_order()

            while self._pending_order:
                review_id = self._pending_order.popleft()
                item = self._items.get(review_id)
                if item is None or item.status != ReviewStatus.PENDING:
                    continue

                claimed = item.model_copy(
                    update={
                        "status": ReviewStatus.IN_PROGRESS,
                        "assigned_to": reviewer_id,
                        "updated_at": self._utcnow(),
                    }
                )
                self._items[review_id] = claimed
                return claimed

            return None

    def assign(self, review_id: str, reviewer_id: str) -> ReviewQueueItem:
        with self._lock:
            item = self._require(review_id)
            updated = item.model_copy(
                update={
                    "assigned_to": reviewer_id,
                    "status": ReviewStatus.IN_PROGRESS,
                    "updated_at": self._utcnow(),
                }
            )
            self._items[review_id] = updated
            self._remove_from_pending(review_id)
            return updated

    def complete(self, review_id: str) -> ReviewQueueItem:
        with self._lock:
            item = self._require(review_id)
            updated = item.model_copy(
                update={
                    "status": ReviewStatus.COMPLETED,
                    "updated_at": self._utcnow(),
                    "completed_at": self._utcnow(),
                }
            )
            self._items[review_id] = updated
            self._remove_from_pending(review_id)
            return updated

    def dismiss(self, review_id: str, reason: Optional[str] = None) -> ReviewQueueItem:
        with self._lock:
            item = self._require(review_id)
            reasons = list(item.reasons)
            if reason:
                reasons = self._dedupe_strings([*reasons, reason])

            updated = item.model_copy(
                update={
                    "status": ReviewStatus.DISMISSED,
                    "reasons": reasons,
                    "updated_at": self._utcnow(),
                    "completed_at": self._utcnow(),
                }
            )
            self._items[review_id] = updated
            self._remove_from_pending(review_id)
            return updated

    def reopen(self, review_id: str) -> ReviewQueueItem:
        with self._lock:
            item = self._require(review_id)
            updated = item.model_copy(
                update={
                    "status": ReviewStatus.PENDING,
                    "assigned_to": None,
                    "updated_at": self._utcnow(),
                    "completed_at": None,
                }
            )
            self._items[review_id] = updated
            self._push_pending(review_id)
            return updated

    def counts(self) -> Dict[str, int]:
        values = {status.value: 0 for status in ReviewStatus}
        for item in self._items.values():
            values[item.status.value] += 1
        return values

    def _update_existing(
        self,
        *,
        review_id: str,
        priority: ReviewPriority,
        title: str,
        summary: str,
        reasons: List[str],
        evidence: List[Dict[str, Any]],
    ) -> ReviewQueueItem:
        item = self._require(review_id)
        updated = item.model_copy(
            update={
                "priority": self._max_priority(item.priority, priority),
                "title": title or item.title,
                "summary": summary or item.summary,
                "reasons": self._dedupe_strings([*item.reasons, *reasons]),
                "evidence": self._dedupe_evidence([*item.evidence, *evidence]),
                "updated_at": self._utcnow(),
                "status": item.status
                if item.status != ReviewStatus.DISMISSED
                else ReviewStatus.PENDING,
                "assigned_to": item.assigned_to
                if item.status == ReviewStatus.IN_PROGRESS
                else None,
                "completed_at": None
                if item.status == ReviewStatus.DISMISSED
                else item.completed_at,
            }
        )
        self._items[review_id] = updated
        if updated.status == ReviewStatus.PENDING:
            self._push_pending(review_id)
        return updated

    def _rebuild_pending_order(self) -> None:
        pending = [
            item.review_id
            for item in sorted(self._items.values(), key=self._sort_key)
            if item.status == ReviewStatus.PENDING
        ]
        self._pending_order = deque(pending)

    def _push_pending(self, review_id: str) -> None:
        if review_id not in self._pending_order:
            self._pending_order.append(review_id)
        self._rebuild_pending_order()

    def _remove_from_pending(self, review_id: str) -> None:
        self._pending_order = deque(
            existing_id for existing_id in self._pending_order if existing_id != review_id
        )

    def _sort_key(self, item: ReviewQueueItem) -> tuple[int, str, str]:
        priority_rank = {
            ReviewPriority.CRITICAL: 0,
            ReviewPriority.HIGH: 1,
            ReviewPriority.MEDIUM: 2,
            ReviewPriority.LOW: 3,
        }
        status_rank = {
            ReviewStatus.PENDING: 0,
            ReviewStatus.IN_PROGRESS: 1,
            ReviewStatus.COMPLETED: 2,
            ReviewStatus.DISMISSED: 3,
        }
        return (
            status_rank[item.status],
            priority_rank[item.priority],
            item.created_at,
        )

    def _coerce_priority(self, value: str) -> ReviewPriority:
        normalized = (value or "medium").strip().lower()
        if normalized == "critical":
            return ReviewPriority.CRITICAL
        if normalized == "high":
            return ReviewPriority.HIGH
        if normalized == "low":
            return ReviewPriority.LOW
        return ReviewPriority.MEDIUM

    def _max_priority(
        self,
        left: ReviewPriority,
        right: ReviewPriority,
    ) -> ReviewPriority:
        rank = {
            ReviewPriority.LOW: 0,
            ReviewPriority.MEDIUM: 1,
            ReviewPriority.HIGH: 2,
            ReviewPriority.CRITICAL: 3,
        }
        return left if rank[left] >= rank[right] else right

    def _dedupe_strings(self, values: List[str]) -> List[str]:
        seen = set()
        result: List[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    def _dedupe_evidence(self, values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        result: List[Dict[str, Any]] = []
        for value in values:
            key = self._freeze(value)
            if key in seen:
                continue
            seen.add(key)
            result.append(value)
        return result

    def _freeze(self, value: Any) -> Any:
        if isinstance(value, dict):
            return tuple(sorted((k, self._freeze(v)) for k, v in value.items()))
        if isinstance(value, list):
            return tuple(self._freeze(v) for v in value)
        if isinstance(value, set):
            return tuple(sorted(self._freeze(v) for v in value))
        return value

    def _require(self, review_id: str) -> ReviewQueueItem:
        item = self._items.get(review_id)
        if item is None:
            raise KeyError(f"review item not found: {review_id}")
        return item

    def _next_review_id(self) -> str:
        review_id = f"rev_{self._counter:05d}"
        self._counter += 1
        return review_id

    def _utcnow(self) -> str:
        return datetime.now(timezone.utc).isoformat()