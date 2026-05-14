from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    if isinstance(value, int | float):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_datetime(value: Any, default: datetime | None = None) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default
        candidate = candidate.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return default
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return default


@dataclass(frozen=True, slots=True)
class ReviewQueueItem:
    review_id: str
    title: str
    category: str
    severity: str
    status: str
    verdict: str
    source: str
    assignee: str = ""
    queued_at: datetime = field(default_factory=_utc_now)
    due_at: datetime | None = None
    requires_human: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "verdict": self.verdict,
            "source": self.source,
            "assignee": self.assignee,
            "queued_at": _isoformat(self.queued_at),
            "due_at": _isoformat(self.due_at),
            "requires_human": self.requires_human,
        }


@dataclass(frozen=True, slots=True)
class ReviewQueue:
    service: str = "ironclaw-security"
    environment: str = "local"
    total_items: int = 0
    pending_items: int = 0
    assigned_items: int = 0
    overdue_items: int = 0
    critical_items: int = 0
    high_items: int = 0
    queue_healthy: bool = True
    escalation_required: bool = False
    average_wait_minutes: int = 0
    items: tuple[ReviewQueueItem, ...] = ()
    checked_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "environment": self.environment,
            "total_items": self.total_items,
            "pending_items": self.pending_items,
            "assigned_items": self.assigned_items,
            "overdue_items": self.overdue_items,
            "critical_items": self.critical_items,
            "high_items": self.high_items,
            "queue_healthy": self.queue_healthy,
            "escalation_required": self.escalation_required,
            "average_wait_minutes": self.average_wait_minutes,
            "items": [item.to_dict() for item in self.items],
            "checked_at": _isoformat(self.checked_at),
        }


def _normalize_item(item: Any) -> ReviewQueueItem | None:
    if not isinstance(item, dict):
        return None

    review_id = _coerce_str(item.get("review_id"))
    if not review_id:
        return None

    queued_at = _coerce_datetime(item.get("queued_at"), _utc_now()) or _utc_now()
    due_at = _coerce_datetime(item.get("due_at"))

    return ReviewQueueItem(
        review_id=review_id,
        title=_coerce_str(item.get("title"), "Untitled review") or "Untitled review",
        category=_coerce_str(item.get("category"), "general") or "general",
        severity=_coerce_str(item.get("severity"), "medium") or "medium",
        status=_coerce_str(item.get("status"), "pending") or "pending",
        verdict=_coerce_str(item.get("verdict"), "review") or "review",
        source=_coerce_str(item.get("source"), "runtime") or "runtime",
        assignee=_coerce_str(item.get("assignee")),
        queued_at=queued_at,
        due_at=due_at,
        requires_human=_coerce_bool(item.get("requires_human"), True),
    )


def default_review_queue() -> ReviewQueue:
    return ReviewQueue()


def build_review_queue(
    data: dict[str, Any] | None = None,
    *,
    baseline: ReviewQueue | None = None,
) -> ReviewQueue:
    source = data or {}
    current = baseline or default_review_queue()

    raw_items = source.get("items")
    if isinstance(raw_items, list):
        normalized_items = tuple(item for entry in raw_items if (item := _normalize_item(entry)) is not None)
        items = normalized_items
    else:
        items = current.items

    total_items = max(0, _coerce_int(source.get("total_items"), current.total_items or len(items)))
    pending_items = max(0, _coerce_int(source.get("pending_items"), current.pending_items))
    assigned_items = max(0, _coerce_int(source.get("assigned_items"), current.assigned_items))
    overdue_items = max(0, _coerce_int(source.get("overdue_items"), current.overdue_items))
    critical_items = max(0, _coerce_int(source.get("critical_items"), current.critical_items))
    high_items = max(0, _coerce_int(source.get("high_items"), current.high_items))
    average_wait_minutes = max(0, _coerce_int(source.get("average_wait_minutes"), current.average_wait_minutes))

    if not source.get("total_items") and items:
        total_items = len(items)
    if not source.get("pending_items") and items:
        pending_items = sum(1 for item in items if item.status.lower() == "pending")
    if not source.get("assigned_items") and items:
        assigned_items = sum(1 for item in items if bool(item.assignee))
    if not source.get("overdue_items") and items:
        now = _utc_now()
        overdue_items = sum(1 for item in items if item.due_at is not None and item.due_at < now and item.status.lower() != "closed")
    if not source.get("critical_items") and items:
        critical_items = sum(1 for item in items if item.severity.lower() == "critical")
    if not source.get("high_items") and items:
        high_items = sum(1 for item in items if item.severity.lower() == "high")

    queue_healthy = _coerce_bool(source.get("queue_healthy"), current.queue_healthy and overdue_items == 0)
    escalation_required = _coerce_bool(
        source.get("escalation_required"),
        current.escalation_required or critical_items > 0 or overdue_items > 0,
    )
    checked_at = _coerce_datetime(source.get("checked_at"), _utc_now()) or _utc_now()

    return ReviewQueue(
        service=_coerce_str(source.get("service"), current.service) or current.service,
        environment=_coerce_str(source.get("environment"), current.environment) or current.environment,
        total_items=total_items,
        pending_items=pending_items,
        assigned_items=assigned_items,
        overdue_items=overdue_items,
        critical_items=critical_items,
        high_items=high_items,
        queue_healthy=queue_healthy,
        escalation_required=escalation_required,
        average_wait_minutes=average_wait_minutes,
        items=items,
        checked_at=checked_at,
    )


def review_queue_summary(queue: ReviewQueue) -> dict[str, Any]:
    human_required_items = sum(1 for item in queue.items if item.requires_human)
    unassigned_items = sum(1 for item in queue.items if not item.assignee)

    return {
        "service": queue.service,
        "environment": queue.environment,
        "queue_healthy": queue.queue_healthy,
        "escalation_required": queue.escalation_required,
        "counts": {
            "total_items": queue.total_items,
            "pending_items": queue.pending_items,
            "assigned_items": queue.assigned_items,
            "unassigned_items": unassigned_items,
            "overdue_items": queue.overdue_items,
            "critical_items": queue.critical_items,
            "high_items": queue.high_items,
            "human_required_items": human_required_items,
        },
        "service_levels": {
            "average_wait_minutes": queue.average_wait_minutes,
            "checked_at": _isoformat(queue.checked_at),
        },
        "items": [item.to_dict() for item in queue.items],
    }
