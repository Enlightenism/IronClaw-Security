from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.persistencebootstrap import build_store

DEFAULT_REVIEW_STATE_TABLE = "review_states"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "y", "on", "enabled", "active"}:
        return True
    if lowered in {"0", "false", "no", "n", "off", "disabled", "inactive"}:
        return False
    return default


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, Mapping):  # Mapping covers dict and mapping-like objects [web:115]
        return dict(value)
    if hasattr(value, "model_dump") and callable(value.model_dump):
        dumped = value.model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "dict") and callable(value.dict):
        dumped = value.dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_") and not callable(item)}
    raise TypeError("review state payload must be a mapping-like object")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _normalize_review_state_payload(
    payload: Mapping[str, Any] | None = None,
    *,
    review_id: str | None = None,
    request_id: str | None = None,
    incident_id: str | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    owner_id: str | None = None,
    reviewer_id: str | None = None,
    queue_id: str | None = None,
    source: str | None = None,
    status: str | None = None,
    decision: str | None = None,
    resolution: str | None = None,
    severity: str | None = None,
    tags: Iterable[Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    notes: str | None = None,
    created_at: str | datetime | None = None,
    updated_at: str | datetime | None = None,
    first_seen_at: str | datetime | None = None,
    last_seen_at: str | datetime | None = None,
    acknowledged_at: str | datetime | None = None,
    resolved_at: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _as_dict(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    resolved_review_id = _text(review_id) or _text(source_payload.get("review_id")) or _text(source_payload.get("id")) or str(uuid4())

    resolved_request_id = _text(request_id) or _text(source_payload.get("request_id")) or _text(source_payload.get("scan_id")) or _text(source_payload.get("execution_id"))

    resolved_incident_id = _text(incident_id) or _text(source_payload.get("incident_id"))

    resolved_org_id = _text(organization_id) or _text(org_id) or _text(source_payload.get("organization_id")) or _text(source_payload.get("org_id"))

    resolved_owner_id = _text(owner_id) or _text(source_payload.get("owner_id"))

    resolved_reviewer_id = _text(reviewer_id) or _text(source_payload.get("reviewer_id")) or _text(source_payload.get("assigned_to"))

    resolved_queue_id = _text(queue_id) or _text(source_payload.get("queue_id")) or "default"

    resolved_source = _text(source) or _text(source_payload.get("source")) or "orchestrator"

    resolved_status = _text(status) or _text(source_payload.get("status")) or "pending"

    resolved_decision = _text(decision) or _text(source_payload.get("decision"))

    resolved_resolution = _text(resolution) or _text(source_payload.get("resolution"))

    resolved_severity = _text(severity) or _text(source_payload.get("severity")) or "medium"

    now_iso = _utc_now_iso()
    created_iso = (created_at if isinstance(created_at, str) else None) or _text(source_payload.get("created_at")) or now_iso
    updated_iso = (updated_at if isinstance(updated_at, str) else None) or _text(source_payload.get("updated_at")) or created_iso

    return {
        "review_id": resolved_review_id,
        "id": resolved_review_id,
        "request_id": resolved_request_id or None,
        "incident_id": resolved_incident_id or None,
        "organization_id": resolved_org_id or None,
        "org_id": resolved_org_id or None,
        "owner_id": resolved_owner_id or None,
        "reviewer_id": resolved_reviewer_id or None,
        "queue_id": resolved_queue_id,
        "source": resolved_source,
        "status": resolved_status,
        "decision": resolved_decision or None,
        "resolution": resolved_resolution or None,
        "severity": resolved_severity,
        "notes": _text(notes) or _text(source_payload.get("notes")),
        "tags": _as_list(tags if tags is not None else source_payload.get("tags")),
        "metadata": _as_dict(metadata if metadata is not None else source_payload.get("metadata")),
        "created_at": created_iso,
        "updated_at": updated_iso,
        "first_seen_at": (_text(first_seen_at) or _text(source_payload.get("first_seen_at")) or created_iso),
        "last_seen_at": (_text(last_seen_at) or _text(source_payload.get("last_seen_at")) or updated_iso),
        "acknowledged_at": _text(
            acknowledged_at if isinstance(acknowledged_at, str) else source_payload.get("acknowledged_at"),
        )
        or None,
        "resolved_at": _text(
            resolved_at if isinstance(resolved_at, str) else source_payload.get("resolved_at"),
        )
        or None,
        "open": _bool(
            source_payload.get("open"),
            default=resolved_status.lower() not in {"resolved", "dismissed", "closed"},
        ),
    }


@dataclass(slots=True)  # slots keep this orchestration state container lean [web:121][web:124]
class ReviewStateStore:
    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_REVIEW_STATE_TABLE

    @property
    def backend_name(self) -> str:
        return str(getattr(self.backend, "backend_name", "memory"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "table_name": self.table_name,
            "ready": True,
        }

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        probe = getattr(self.backend, "healthcheck", None)
        if callable(probe):
            return bool(probe())
        return True

    # Core CRUD

    def create_state(self, payload: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        record = _normalize_review_state_payload(payload, **kwargs)
        inserted = self.backend.insert(self.table_name, record)
        if isinstance(inserted, list) and inserted:
            return dict(inserted[0])
        if isinstance(inserted, dict):
            return dict(inserted)
        return record

    def create(self, payload: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.create_state(payload, **kwargs)

    def upsert_state(self, payload: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        record = _normalize_review_state_payload(payload, **kwargs)
        existing = self.get_state(record["review_id"])
        if existing is None and record.get("request_id"):
            existing = self.get_by_request_id(record["request_id"])
        if existing is None:
            return self.create_state(record)
        return self.update_state(record["review_id"], record) or record

    # Lookup

    def get_state(self, review_id: str) -> dict[str, Any] | None:
        if not _text(review_id):
            raise ValueError("review_id is required")

        for key in ("review_id", "id"):
            rows = self.backend.select(self.table_name, filters={key: review_id}, limit=1)
            if rows:
                return dict(rows[0])
        return None

    def get(self, review_id: str) -> dict[str, Any] | None:
        return self.get_state(review_id)

    def get_by_request_id(self, request_id: str) -> dict[str, Any] | None:
        normalized = _text(request_id)
        if not normalized:
            raise ValueError("request_id is required")

        rows = self.backend.select(self.table_name, filters={"request_id": normalized}, limit=1)
        if rows:
            return dict(rows[0])
        return None

    def exists(self, review_id: str) -> bool:
        return self.get_state(review_id) is not None

    # Listing

    def list_states(
        self,
        *,
        limit: int = 100,
        filters: Mapping[str, Any] | None = None,
        organization_id: str | None = None,
        owner_id: str | None = None,
        queue_id: str | None = None,
        status: str | None = None,
        open_only: bool | None = None,
    ) -> list[dict[str, Any]]:
        query_filters: dict[str, Any] = dict(filters or {})
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if owner_id:
            query_filters.setdefault("owner_id", owner_id)
        if queue_id:
            query_filters.setdefault("queue_id", queue_id)
        if status:
            query_filters.setdefault("status", status)
        if open_only:
            query_filters.setdefault("open", True)

        rows = self.backend.select(self.table_name, filters=query_filters or None, limit=limit)
        items = [dict(row) for row in rows]
        items.sort(
            key=lambda row: _text(row.get("updated_at") or row.get("created_at")),
            reverse=True,
        )
        return items

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_states(**kwargs)

    # Updates

    def update_state(self, review_id: str, updates: Mapping[str, Any]) -> dict[str, Any] | None:
        existing = self.get_state(review_id)
        if existing is None:
            return None

        merged = dict(existing)
        merged.update(_as_dict(updates))
        merged["review_id"] = existing.get("review_id") or existing.get("id") or review_id
        merged["id"] = merged["review_id"]
        merged["updated_at"] = _utc_now_iso()

        normalized = _normalize_review_state_payload(merged)

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"review_id": review_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"id": review_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        return normalized

    def update(self, review_id: str, updates: Mapping[str, Any]) -> dict[str, Any] | None:
        return self.update_state(review_id, updates)

    # State transitions

    def mark_in_queue(self, review_id: str, queue_id: str | None = None) -> dict[str, Any] | None:
        updates: dict[str, Any] = {"status": "queued"}
        if queue_id:
            updates["queue_id"] = _text(queue_id)
        return self.update_state(review_id, updates)

    def mark_in_review(self, review_id: str, reviewer_id: str | None = None) -> dict[str, Any] | None:
        updates: dict[str, Any] = {"status": "in_review", "open": True}
        if reviewer_id:
            updates["reviewer_id"] = _text(reviewer_id)
        return self.update_state(review_id, updates)

    def acknowledge(self, review_id: str, reviewer_id: str | None = None) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "acknowledged",
            "acknowledged_at": _utc_now_iso(),
            "open": True,
        }
        if reviewer_id:
            updates["reviewer_id"] = _text(reviewer_id)
        return self.update_state(review_id, updates)

    def resolve(
        self,
        review_id: str,
        *,
        decision: str = "approved",
        resolution: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "resolved",
            "decision": _text(decision),
            "resolution": _text(resolution) or _text(notes),
            "resolved_at": _utc_now_iso(),
            "open": False,
        }
        return self.update_state(review_id, updates)

    def dismiss(
        self,
        review_id: str,
        *,
        resolution: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "dismissed",
            "decision": "dismissed",
            "resolution": _text(resolution) or _text(notes),
            "resolved_at": _utc_now_iso(),
            "open": False,
        }
        return self.update_state(review_id, updates)

    # Delete

    def delete_state(self, review_id: str) -> dict[str, Any] | None:
        if not _text(review_id):
            raise ValueError("review_id is required")

        deleted = self.backend.delete(self.table_name, filters={"review_id": review_id})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        deleted = self.backend.delete(self.table_name, filters={"id": review_id})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        return None

    def delete(self, review_id: str) -> dict[str, Any] | None:
        return self.delete_state(review_id)

    # Summary

    def summarize(
        self,
        *,
        organization_id: str | None = None,
        owner_id: str | None = None,
        limit: int = 1_000,
    ) -> dict[str, Any]:
        states = self.list_states(
            limit=limit,
            organization_id=organization_id,
            owner_id=owner_id,
        )

        by_status: dict[str, int] = {}
        by_decision: dict[str, int] = {}
        open_count = 0

        for state in states:
            status = _text(state.get("status"), "unknown")
            decision = _text(state.get("decision"), "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            by_decision[decision] = by_decision.get(decision, 0) + 1
            if _bool(state.get("open"), default=status.lower() not in {"resolved", "dismissed", "closed"}):
                open_count += 1

        return {
            "total_reviews": len(states),
            "open_reviews": open_count,
            "by_status": by_status,
            "by_decision": by_decision,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


def build_review_state_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_REVIEW_STATE_TABLE,
    **store_kwargs: Any,
) -> ReviewStateStore:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return ReviewStateStore(backend=resolved_backend, table_name=table_name)


def create_review_state_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_REVIEW_STATE_TABLE,
    **store_kwargs: Any,
) -> ReviewStateStore:
    return build_review_state_store(backend=backend, table_name=table_name, **store_kwargs)


def get_review_state_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_REVIEW_STATE_TABLE,
    **store_kwargs: Any,
) -> ReviewStateStore:
    return build_review_state_store(backend=backend, table_name=table_name, **store_kwargs)
