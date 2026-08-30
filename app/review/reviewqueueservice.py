from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from app.services.incidentstore import build_incident_store
from app.services.quarantinestore import build_quarantine_store


class ReviewPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    DISMISSED = "dismissed"


class ReviewSource(StrEnum):
    INCIDENT = "incident"
    SESSION = "session"
    SIGNAL = "signal"
    ARTIFACT = "artifact"
    MANUAL = "manual"


class ReviewQueueItem:
    def __init__(
        self,
        *,
        review_id: str,
        source: ReviewSource,
        source_id: str,
        priority: ReviewPriority,
        status: ReviewStatus = ReviewStatus.PENDING,
        title: str,
        summary: str,
        reasons: list[str] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        assigned_to: str | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        self.review_id = review_id
        self.source = source
        self.source_id = source_id
        self.priority = priority
        self.status = status
        self.title = title
        self.summary = summary
        self.reasons = list(reasons or [])
        self.evidence = list(evidence or [])
        self.assigned_to = assigned_to
        self.created_at = created_at or _utc_now()
        self.updated_at = updated_at or self.created_at
        self.completed_at = completed_at

    def model_copy(self, *, update: dict[str, Any] | None = None) -> ReviewQueueItem:
        data = {
            "review_id": self.review_id,
            "source": self.source,
            "source_id": self.source_id,
            "priority": self.priority,
            "status": self.status,
            "title": self.title,
            "summary": self.summary,
            "reasons": list(self.reasons),
            "evidence": list(self.evidence),
            "assigned_to": self.assigned_to,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
        }
        if update:
            data.update(update)
        return ReviewQueueItem(
            review_id=data["review_id"],
            source=data["source"],
            source_id=data["source_id"],
            priority=data["priority"],
            status=data["status"],
            title=data["title"],
            summary=data["summary"],
            reasons=data["reasons"],
            evidence=data["evidence"],
            assigned_to=data["assigned_to"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            completed_at=data["completed_at"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "source": self.source.value,
            "source_id": self.source_id,
            "priority": self.priority.value,
            "status": self.status.value,
            "title": self.title,
            "summary": self.summary,
            "reasons": list(self.reasons),
            "evidence": list(self.evidence),
            "assigned_to": self.assigned_to,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
        }


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump") and callable(value.model_dump):
        dumped = value.model_dump()
        if isinstance(dumped, dict):
            return dict(dumped)
    if hasattr(value, "dict") and callable(value.dict):
        dumped = value.dict()
        if isinstance(dumped, dict):
            return dict(dumped)
    if hasattr(value, "__dict__"):
        return {key: val for key, val in vars(value).items() if not key.startswith("_") and not callable(val)}
    raise TypeError("value is not serializable to dict")


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _normalize_priority(value: str | None, *, severity: str | None = None) -> str:
    priority = _string(value).lower()
    if priority:
        return priority
    severity_value = _string(severity).lower()
    if severity_value in {"critical", "high", "medium", "low"}:
        return severity_value
    return "medium"


def _normalize_status(value: str | None) -> str:
    status = _string(value).lower()
    if status:
        return status
    return "pending"


def _normalize_queue_item(
    payload: dict[str, Any] | None = None,
    *,
    review_id: str | None = None,
    incident_id: str | None = None,
    quarantine_id: str | None = None,
    organization_id: str | None = None,
    owner_id: str | None = None,
    item_type: str | None = None,
    title: str | None = None,
    summary: str | None = None,
    status: str | None = None,
    priority: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    category: str | None = None,
    assigned_to: str | None = None,
    requested_by: str | None = None,
    verdict: str | None = None,
    tags: list[Any] | None = None,
    evidence: list[Any] | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: str | None = None,
    updated_at: str | None = None,
    due_at: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _mapping(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    resolved_review_id = _string(review_id) or _string(source_payload.get("review_id")) or _string(source_payload.get("id")) or str(uuid4())
    resolved_incident_id = _string(incident_id) or _string(source_payload.get("incident_id"))
    resolved_quarantine_id = _string(quarantine_id) or _string(source_payload.get("quarantine_id"))
    resolved_item_type = _string(item_type) or _string(source_payload.get("item_type")) or ("incident" if resolved_incident_id else "quarantine" if resolved_quarantine_id else "review")
    resolved_severity = _string(severity) or _string(source_payload.get("severity")) or "medium"
    resolved_priority = _normalize_priority(priority or source_payload.get("priority"), severity=resolved_severity)
    resolved_status = _normalize_status(status or source_payload.get("status"))
    resolved_title = _string(title) or _string(source_payload.get("title")) or _string(source_payload.get("summary")) or f"{resolved_item_type.title()} review"
    resolved_summary = _string(summary) or _string(source_payload.get("summary")) or resolved_title
    resolved_created_at = _string(created_at) or _string(source_payload.get("created_at")) or _utc_now()
    resolved_updated_at = _string(updated_at) or _string(source_payload.get("updated_at")) or resolved_created_at

    return {
        "review_id": resolved_review_id,
        "id": resolved_review_id,
        "incident_id": resolved_incident_id or None,
        "quarantine_id": resolved_quarantine_id or None,
        "organization_id": _string(organization_id) or _string(source_payload.get("organization_id")) or None,
        "owner_id": _string(owner_id) or _string(source_payload.get("owner_id")) or None,
        "item_type": resolved_item_type,
        "title": resolved_title,
        "summary": resolved_summary,
        "status": resolved_status,
        "priority": resolved_priority,
        "severity": resolved_severity,
        "source": _string(source) or _string(source_payload.get("source")) or "ironclaw",
        "category": _string(category) or _string(source_payload.get("category")) or resolved_item_type,
        "assigned_to": _string(assigned_to) or _string(source_payload.get("assigned_to")) or None,
        "requested_by": _string(requested_by) or _string(source_payload.get("requested_by")) or None,
        "verdict": _string(verdict) or _string(source_payload.get("verdict")) or "pending",
        "tags": _listify(tags if tags is not None else source_payload.get("tags")),
        "evidence": _listify(evidence if evidence is not None else source_payload.get("evidence")),
        "metadata": metadata if isinstance(metadata, dict) else _mapping(source_payload.get("metadata")),
        "created_at": resolved_created_at,
        "updated_at": resolved_updated_at,
        "due_at": _string(due_at) or _string(source_payload.get("due_at")) or None,
    }


@dataclass(slots=True)
class ReviewQueueService:
    incident_store: Any = field(default_factory=build_incident_store)
    quarantine_store: Any = field(default_factory=build_quarantine_store)
    _items: dict[str, ReviewQueueItem] = field(default_factory=dict)
    _index_by_source: dict[tuple[str, str], str] = field(default_factory=dict)
    _counter: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": True,
            "size": len(self._items),
            "stores": {
                "incident_store": bool(self.incident_store),
                "quarantine_store": bool(self.quarantine_store),
            },
        }

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        return True

    def _next_review_id(self) -> str:
        review_id = f"rev_{self._counter:05d}"
        self._counter += 1
        return review_id

    def _dedupe_strings(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    def _dedupe_evidence(self, values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[Any] = set()
        result: list[dict[str, Any]] = []
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

    def _store_item(self, item: ReviewQueueItem) -> ReviewQueueItem:
        key = (item.source.value, item.source_id)
        existing_id = self._index_by_source.get(key)
        if existing_id is not None:
            existing = self._items.get(existing_id)
            if existing is not None:
                updated = existing.model_copy(
                    update={
                        "priority": self._max_priority(existing.priority, item.priority),
                        "title": item.title or existing.title,
                        "summary": item.summary or existing.summary,
                        "reasons": self._dedupe_strings([*existing.reasons, *item.reasons]),
                        "evidence": self._dedupe_evidence([*existing.evidence, *item.evidence]),
                        "updated_at": item.updated_at or _utc_now(),
                        "status": existing.status if existing.status != ReviewStatus.DISMISSED else ReviewStatus.PENDING,
                        "assigned_to": existing.assigned_to if existing.status == ReviewStatus.IN_PROGRESS else None,
                        "completed_at": None if existing.status == ReviewStatus.DISMISSED else existing.completed_at,
                    },
                )
                self._items[existing_id] = updated
                return updated
        item.review_id = item.review_id or self._next_review_id()
        self._items[item.review_id] = item
        self._index_by_source[key] = item.review_id
        return item

    def _max_priority(self, left: ReviewPriority, right: ReviewPriority) -> ReviewPriority:
        rank = {ReviewPriority.LOW: 0, ReviewPriority.MEDIUM: 1, ReviewPriority.HIGH: 2, ReviewPriority.CRITICAL: 3}
        return left if rank[left] >= rank[right] else right

    def submit(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        item = _normalize_queue_item(payload, **kwargs)
        record = ReviewQueueItem(
            review_id=item["review_id"],
            source=ReviewSource(item.get("source", "manual").lower()) if str(item.get("source", "manual")).lower() in {member.value for member in ReviewSource} else ReviewSource.MANUAL,
            source_id=str(item.get("incident_id") or item.get("quarantine_id") or item.get("review_id") or "unknown"),
            priority=self._coerce_priority(item.get("priority") or item.get("severity") or "medium"),
            status=ReviewStatus(item.get("status", ReviewStatus.PENDING.value)) if str(item.get("status", ReviewStatus.PENDING.value)).lower() in {member.value for member in ReviewStatus} else ReviewStatus.PENDING,
            title=item.get("title") or "Queued review",
            summary=item.get("summary") or item.get("title") or "Queued review",
            reasons=self._dedupe_strings(list(item.get("tags") or [])),
            evidence=self._dedupe_evidence(list(item.get("evidence") or [])),
            assigned_to=item.get("assigned_to"),
            created_at=item.get("created_at") or _utc_now(),
            updated_at=item.get("updated_at") or item.get("created_at") or _utc_now(),
            completed_at=item.get("completed_at"),
        )
        stored = self._store_item(record)
        return stored.to_dict()

    def enqueue(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.submit(payload, **kwargs)

    def create_review(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.submit(payload, **kwargs)

    def queue_incident_review(
        self,
        incident_id: str,
        *,
        priority: str | None = None,
        assigned_to: str | None = None,
        requested_by: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        incident = self.incident_store.get_incident(incident_id)
        if incident is None:
            raise ValueError("incident not found")
        return self.submit(
            {
                "incident_id": incident_id,
                "item_type": "incident",
                "title": _string(incident.get("title")) or "Incident review",
                "summary": _string(incident.get("summary")) or _string(incident.get("description")) or "Incident review required",
                "severity": _string(incident.get("severity")) or "medium",
                "priority": priority or _string(incident.get("priority")) or _string(incident.get("severity")) or "medium",
                "organization_id": _string(incident.get("organization_id")),
                "owner_id": _string(incident.get("owner_id")),
                "source": _string(incident.get("source")) or "incident_store",
                "category": _string(incident.get("category")) or "incident",
                "assigned_to": assigned_to,
                "requested_by": requested_by,
                "metadata": metadata or {"origin": "incident_store"},
                "evidence": incident.get("evidence") or [],
                "tags": incident.get("tags") or [],
            },
        )

    def queue_quarantine_review(
        self,
        quarantine_id: str,
        *,
        priority: str | None = None,
        assigned_to: str | None = None,
        requested_by: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        item = self.quarantine_store.get_quarantine_item(quarantine_id)
        if item is None:
            raise ValueError("quarantine item not found")
        return self.submit(
            {
                "quarantine_id": quarantine_id,
                "incident_id": _string(item.get("incident_id")) or None,
                "item_type": "quarantine",
                "title": _string(item.get("filename")) or _string(item.get("item_id")) or "Quarantine review",
                "summary": _string(item.get("reason")) or "Quarantine review required",
                "severity": _string(item.get("severity")) or "medium",
                "priority": priority or _string(item.get("severity")) or "medium",
                "organization_id": _string(item.get("organization_id")),
                "owner_id": _string(item.get("owner_id")),
                "source": _string(item.get("source")) or "quarantine_store",
                "category": _string(item.get("category")) or "quarantine",
                "assigned_to": assigned_to,
                "requested_by": requested_by,
                "metadata": metadata or {"origin": "quarantine_store"},
                "evidence": item.get("evidence") or [],
                "tags": item.get("tags") or [],
            },
        )

    def list_reviews(
        self,
        *,
        status: str | None = None,
        assigned_to: str | None = None,
        priority: str | None = None,
        item_type: str | None = None,
        organization_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        items = list(self._items.values())
        if status:
            wanted = _normalize_status(status)
            items = [item for item in items if _normalize_status(item.status.value) == wanted]
        if assigned_to:
            items = [item for item in items if _string(item.assigned_to) == _string(assigned_to)]
        if priority:
            wanted = _normalize_priority(priority)
            items = [item for item in items if _normalize_priority(item.priority.value) == wanted]
        if item_type:
            items = [item for item in items if _string(item.source.value) == _string(item_type)]
        if organization_id:
            items = [item for item in items if item.source_id == _string(organization_id)]
        items.sort(
            key=lambda item: (
                item.priority == ReviewPriority.CRITICAL,
                item.priority == ReviewPriority.HIGH,
                _string(item.updated_at),
            ),
            reverse=True,
        )
        return [item.to_dict() for item in items[:limit]]

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_reviews(**kwargs)

    def get_review(self, review_id: str) -> dict[str, Any] | None:
        key = _string(review_id)
        if not key:
            raise ValueError("review_id is required")
        item = self._items.get(key)
        return item.to_dict() if item else None

    def get(self, review_id: str) -> ReviewQueueItem | None:
        key = _string(review_id)
        if not key:
            raise ValueError("review_id is required")
        return self._items.get(key)

    def assign_review(self, review_id: str, assigned_to: str) -> dict[str, Any] | None:
        item = self._items.get(_string(review_id))
        if item is None:
            return None
        item.assigned_to = _string(assigned_to) or None
        item.status = ReviewStatus.IN_PROGRESS
        item.updated_at = _utc_now()
        return item.to_dict()

    def start_review(self, review_id: str, *, assigned_to: str | None = None) -> dict[str, Any] | None:
        item = self._items.get(_string(review_id))
        if item is None:
            return None
        if assigned_to is not None:
            item.assigned_to = _string(assigned_to) or None
        item.status = ReviewStatus.IN_PROGRESS
        item.updated_at = _utc_now()
        return item.to_dict()

    def complete_review(
        self,
        review_id: str,
        *,
        verdict: str,
        notes: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        item = self._items.get(_string(review_id))
        if item is None:
            return None
        item.status = ReviewStatus.COMPLETED
        item.completed_at = _utc_now()
        item.updated_at = _utc_now()
        item.verdict = _string(verdict) or "completed"
        merged_metadata = {}
        if getattr(item, "metadata", None):
            merged_metadata = dict(item.metadata)
        if notes is not None:
            merged_metadata["notes"] = notes
        if metadata:
            merged_metadata.update(metadata)
        item.metadata = merged_metadata
        return item.to_dict()

    def reject_review(
        self,
        review_id: str,
        *,
        notes: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        item = self._items.get(_string(review_id))
        if item is None:
            return None
        merged_metadata = {}
        if getattr(item, "metadata", None):
            merged_metadata = dict(item.metadata)
        if notes is not None:
            merged_metadata["notes"] = notes
        if metadata:
            merged_metadata.update(metadata)
        item.metadata = merged_metadata
        item.status = ReviewStatus.DISMISSED
        item.verdict = "rejected"
        item.updated_at = _utc_now()
        return item.to_dict()

    def cancel_review(self, review_id: str) -> dict[str, Any] | None:
        item = self._items.get(_string(review_id))
        if item is None:
            return None
        item.status = ReviewStatus.DISMISSED
        item.updated_at = _utc_now()
        return item.to_dict()

    def delete_review(self, review_id: str) -> dict[str, Any] | None:
        key = _string(review_id)
        if not key:
            raise ValueError("review_id is required")
        item = self._items.pop(key, None)
        return item.to_dict() if item else None

    def summarize(self) -> dict[str, Any]:
        items = list(self._items.values())
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for item in items:
            status = item.status.value
            priority = item.priority.value
            by_status[status] = by_status.get(status, 0) + 1
            by_priority[priority] = by_priority.get(priority, 0) + 1
            by_type[item.source.value] = by_type.get(item.source.value, 0) + 1
        return {
            "total": len(items),
            "pending": by_status.get(ReviewStatus.PENDING.value, 0),
            "in_review": by_status.get(ReviewStatus.IN_PROGRESS.value, 0),
            "completed": by_status.get(ReviewStatus.COMPLETED.value, 0),
            "rejected": by_status.get("rejected", 0),
            "cancelled": by_status.get(ReviewStatus.DISMISSED.value, 0),
            "by_status": by_status,
            "by_priority": by_priority,
            "by_type": by_type,
        }

    def list_items(
        self,
        *,
        status: ReviewStatus | None = None,
        assigned_to: str | None = None,
    ) -> list[ReviewQueueItem]:
        items = list(self._items.values())
        if status is not None:
            items = [item for item in items if item.status == status]
        if assigned_to is not None:
            items = [item for item in items if item.assigned_to == assigned_to]
        return list(items)

    def enqueue_model(
        self,
        *,
        source: ReviewSource,
        source_id: str,
        priority: ReviewPriority | str,
        title: str,
        summary: str,
        reasons: list[str] | None = None,
        evidence: list[dict[str, Any]] | None = None,
    ) -> ReviewQueueItem:
        normalized_priority = priority if isinstance(priority, ReviewPriority) else ReviewPriority(priority)
        item = ReviewQueueItem(
            review_id=self._next_review_id(),
            source=source,
            source_id=source_id,
            priority=normalized_priority,
            title=title,
            summary=summary,
            reasons=self._dedupe_strings(list(reasons or [])),
            evidence=self._dedupe_evidence(list(evidence or [])),
        )
        return self._store_item(item)

    def escalate_incident(
        self,
        *,
        incident_id: str,
        priority: str,
        title: str,
        summary: str,
        reasons: list[str] | None = None,
        evidence: list[dict[str, Any]] | None = None,
    ) -> ReviewQueueItem:
        key = (ReviewSource.INCIDENT.value, incident_id)
        existing_id = self._index_by_source.get(key)
        if existing_id is not None:
            existing = self._items.get(existing_id)
            if existing is not None:
                updated = existing.model_copy(
                    update={
                        "priority": self._max_priority(existing.priority, self._coerce_priority(priority)),
                        "title": title or existing.title,
                        "summary": summary or existing.summary,
                        "reasons": self._dedupe_strings([*existing.reasons, *(reasons or [])]),
                        "evidence": self._dedupe_evidence([*existing.evidence, *(evidence or [])]),
                        "updated_at": _utc_now(),
                    },
                )
                self._items[existing.review_id] = updated
                self._index_by_source[key] = existing.review_id
                return updated
        return self.enqueue_model(
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
        reasons: list[str] | None = None,
        evidence: list[dict[str, Any]] | None = None,
    ) -> ReviewQueueItem:
        return self.enqueue_model(
            source=ReviewSource.SESSION,
            source_id=session_id,
            priority=self._coerce_priority(priority),
            title=title,
            summary=summary,
            reasons=reasons,
            evidence=evidence,
        )

    def claim_next(self, reviewer_id: str) -> ReviewQueueItem | None:
        return None

    def assign(self, review_id: str, reviewer_id: str) -> ReviewQueueItem:
        item = self._items.get(review_id)
        if item is None:
            raise KeyError(f"review item not found: {review_id}")
        item.assigned_to = reviewer_id
        item.status = ReviewStatus.IN_PROGRESS
        item.updated_at = _utc_now()
        return item

    def complete(self, review_id: str) -> ReviewQueueItem:
        item = self._items.get(review_id)
        if item is None:
            raise KeyError(f"review item not found: {review_id}")
        item.status = ReviewStatus.COMPLETED
        item.updated_at = _utc_now()
        item.completed_at = _utc_now()
        return item

    def dismiss(self, review_id: str, reason: str | None = None) -> ReviewQueueItem:
        item = self._items.get(review_id)
        if item is None:
            raise KeyError(f"review item not found: {review_id}")
        reasons = list(item.reasons)
        if reason:
            reasons.append(reason)
        item.reasons = self._dedupe_strings(reasons)
        item.status = ReviewStatus.DISMISSED
        item.updated_at = _utc_now()
        item.completed_at = _utc_now()
        return item

    def reopen(self, review_id: str) -> ReviewQueueItem:
        item = self._items.get(review_id)
        if item is None:
            raise KeyError(f"review item not found: {review_id}")
        item.status = ReviewStatus.PENDING
        item.assigned_to = None
        item.updated_at = _utc_now()
        item.completed_at = None
        return item

    def counts(self) -> dict[str, int]:
        values = {status.value: 0 for status in ReviewStatus}
        for item in self._items.values():
            status = item.status.value
            values[status] = values.get(status, 0) + 1
        return values

    def _coerce_priority(self, value: str) -> ReviewPriority:
        normalized = (value or "medium").strip().lower()
        if normalized == "critical":
            return ReviewPriority.CRITICAL
        if normalized == "high":
            return ReviewPriority.HIGH
        if normalized == "low":
            return ReviewPriority.LOW
        return ReviewPriority.MEDIUM


def build_review_queue_service(
    *,
    incident_store: Any | None = None,
    quarantine_store: Any | None = None,
) -> ReviewQueueService:
    return ReviewQueueService(
        incident_store=incident_store or build_incident_store(),
        quarantine_store=quarantine_store or build_quarantine_store(),
    )


def create_review_queue_service(
    *,
    incident_store: Any | None = None,
    quarantine_store: Any | None = None,
) -> ReviewQueueService:
    return build_review_queue_service(incident_store=incident_store, quarantine_store=quarantine_store)


def get_review_queue_service(
    *,
    incident_store: Any | None = None,
    quarantine_store: Any | None = None,
) -> ReviewQueueService:
    return build_review_queue_service(incident_store=incident_store, quarantine_store=quarantine_store)


__all__ = [
    "ReviewPriority",
    "ReviewStatus",
    "ReviewSource",
    "ReviewQueueItem",
    "ReviewQueueService",
    "build_review_queue_service",
    "create_review_queue_service",
    "get_review_queue_service",
]
