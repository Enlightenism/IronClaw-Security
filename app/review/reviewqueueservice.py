from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.services.incidentstore import build_incident_store
from app.services.quarantinestore import build_quarantine_store


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
        return {
            key: val
            for key, val in vars(value).items()
            if not key.startswith("_") and not callable(val)
        }
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

    resolved_review_id = (
        _string(review_id)
        or _string(source_payload.get("review_id"))
        or _string(source_payload.get("id"))
        or str(uuid4())
    )

    resolved_incident_id = (
        _string(incident_id)
        or _string(source_payload.get("incident_id"))
    )
    resolved_quarantine_id = (
        _string(quarantine_id)
        or _string(source_payload.get("quarantine_id"))
    )

    resolved_item_type = (
        _string(item_type)
        or _string(source_payload.get("item_type"))
        or ("incident" if resolved_incident_id else "quarantine" if resolved_quarantine_id else "review")
    )

    resolved_severity = (
        _string(severity)
        or _string(source_payload.get("severity"))
        or "medium"
    )

    resolved_priority = _normalize_priority(
        priority or source_payload.get("priority"),
        severity=resolved_severity,
    )

    resolved_status = _normalize_status(status or source_payload.get("status"))

    resolved_title = (
        _string(title)
        or _string(source_payload.get("title"))
        or _string(source_payload.get("summary"))
        or f"{resolved_item_type.title()} review"
    )

    resolved_summary = (
        _string(summary)
        or _string(source_payload.get("summary"))
        or resolved_title
    )

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
    _items: dict[str, dict[str, Any]] = field(default_factory=dict)

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

    def submit(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        item = _normalize_queue_item(payload, **kwargs)
        self._items[item["review_id"]] = item
        return dict(item)

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
            }
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
            }
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
            items = [item for item in items if _normalize_status(item.get("status")) == wanted]
        if assigned_to:
            items = [item for item in items if _string(item.get("assigned_to")) == _string(assigned_to)]
        if priority:
            wanted = _normalize_priority(priority)
            items = [item for item in items if _normalize_priority(item.get("priority")) == wanted]
        if item_type:
            items = [item for item in items if _string(item.get("item_type")) == _string(item_type)]
        if organization_id:
            items = [item for item in items if _string(item.get("organization_id")) == _string(organization_id)]

        items.sort(
            key=lambda item: (
                item.get("priority") == "critical",
                item.get("priority") == "high",
                _string(item.get("updated_at")),
            ),
            reverse=True,
        )
        return [dict(item) for item in items[:limit]]

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_reviews(**kwargs)

    def get_review(self, review_id: str) -> dict[str, Any] | None:
        key = _string(review_id)
        if not key:
            raise ValueError("review_id is required")
        item = self._items.get(key)
        return dict(item) if item else None

    def get(self, review_id: str) -> dict[str, Any] | None:
        return self.get_review(review_id)

    def assign_review(self, review_id: str, assigned_to: str) -> dict[str, Any] | None:
        item = self._items.get(_string(review_id))
        if item is None:
            return None
        item["assigned_to"] = _string(assigned_to) or None
        item["status"] = "in_review"
        item["updated_at"] = _utc_now()
        self._items[item["review_id"]] = item
        return dict(item)

    def start_review(self, review_id: str, *, assigned_to: str | None = None) -> dict[str, Any] | None:
        item = self._items.get(_string(review_id))
        if item is None:
            return None
        if assigned_to is not None:
            item["assigned_to"] = _string(assigned_to) or None
        item["status"] = "in_review"
        item["updated_at"] = _utc_now()
        self._items[item["review_id"]] = item
        return dict(item)

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

        item["status"] = "completed"
        item["verdict"] = _string(verdict) or "completed"
        item["updated_at"] = _utc_now()

        merged_metadata = _mapping(item.get("metadata"))
        if notes is not None:
            merged_metadata["notes"] = notes
        if metadata:
            merged_metadata.update(metadata)
        item["metadata"] = merged_metadata

        self._items[item["review_id"]] = item

        incident_id = _string(item.get("incident_id"))
        quarantine_id = _string(item.get("quarantine_id"))

        if incident_id:
            incident_updates: dict[str, Any] = {
                "verdict": item["verdict"],
                "status": "resolved" if item["verdict"] in {"allow", "approved", "resolved"} else "in_progress",
                "metadata": {"review_id": item["review_id"], **merged_metadata},
            }
            self.incident_store.update_incident(incident_id, incident_updates)

        if quarantine_id:
            if item["verdict"] in {"allow", "approved", "release", "released", "restore", "restored"}:
                self.quarantine_store.release_item(
                    quarantine_id,
                    verdict=item["verdict"],
                    metadata={"review_id": item["review_id"], **merged_metadata},
                )
            elif item["verdict"] in {"block", "blocked", "purge", "purged"}:
                self.quarantine_store.purge_item(
                    quarantine_id,
                    verdict=item["verdict"],
                )

        return dict(item)

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
        merged_metadata = _mapping(item.get("metadata"))
        if notes is not None:
            merged_metadata["notes"] = notes
        if metadata:
            merged_metadata.update(metadata)
        item["metadata"] = merged_metadata
        item["status"] = "rejected"
        item["verdict"] = "rejected"
        item["updated_at"] = _utc_now()
        self._items[item["review_id"]] = item
        return dict(item)

    def cancel_review(self, review_id: str) -> dict[str, Any] | None:
        item = self._items.get(_string(review_id))
        if item is None:
            return None
        item["status"] = "cancelled"
        item["updated_at"] = _utc_now()
        self._items[item["review_id"]] = item
        return dict(item)

    def delete_review(self, review_id: str) -> dict[str, Any] | None:
        key = _string(review_id)
        if not key:
            raise ValueError("review_id is required")
        item = self._items.pop(key, None)
        return dict(item) if item else None

    def summarize(self) -> dict[str, Any]:
        items = list(self._items.values())
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        by_type: dict[str, int] = {}

        for item in items:
            status = _normalize_status(item.get("status"))
            priority = _normalize_priority(item.get("priority"))
            item_type = _string(item.get("item_type"), "review")

            by_status[status] = by_status.get(status, 0) + 1
            by_priority[priority] = by_priority.get(priority, 0) + 1
            by_type[item_type] = by_type.get(item_type, 0) + 1

        return {
            "total": len(items),
            "pending": by_status.get("pending", 0),
            "in_review": by_status.get("in_review", 0),
            "completed": by_status.get("completed", 0),
            "rejected": by_status.get("rejected", 0),
            "cancelled": by_status.get("cancelled", 0),
            "by_status": by_status,
            "by_priority": by_priority,
            "by_type": by_type,
        }


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
    return build_review_queue_service(
        incident_store=incident_store,
        quarantine_store=quarantine_store,
    )


def get_review_queue_service(
    *,
    incident_store: Any | None = None,
    quarantine_store: Any | None = None,
) -> ReviewQueueService:
    return build_review_queue_service(
        incident_store=incident_store,
        quarantine_store=quarantine_store,
    )