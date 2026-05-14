from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from heapq import heappop, heappush
from itertools import count
from typing import Any
from uuid import uuid4

from app.orchestrator.reviewstatestore import ReviewStateStore, build_review_state_store

DEFAULT_QUEUE_ID = "default"
DEFAULT_PRIORITY = 100

_STATUS_QUEUED = "queued"
_STATUS_IN_REVIEW = "in_review"
_STATUS_ACKNOWLEDGED = "acknowledged"
_STATUS_RESOLVED = "resolved"
_STATUS_DISMISSED = "dismissed"
_STATUS_CLOSED = "closed"

_TERMINAL_STATUSES = {
    _STATUS_RESOLVED,
    _STATUS_DISMISSED,
    _STATUS_CLOSED,
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _int(value: Any, default: int = DEFAULT_PRIORITY) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
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
    if isinstance(value, Mapping):
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
    raise TypeError("queue item payload must be mapping-like")


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


def _merge_metadata(*parts: Any) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for part in parts:
        if part is None:
            continue
        merged.update(_as_dict(part))
    return merged


def _normalize_queue_item_payload(
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
    priority: int | str | None = None,
    attempts: int | str | None = None,
    max_attempts: int | str | None = None,
    available_at: str | None = None,
    lease_expires_at: str | None = None,
    resolution: str | None = None,
    decision: str | None = None,
    severity: str | None = None,
    tags: Iterable[Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    notes: str | None = None,
    created_at: str | None = None,
    updated_at: str | None = None,
    enqueued_at: str | None = None,
    dequeued_at: str | None = None,
    acknowledged_at: str | None = None,
    resolved_at: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _as_dict(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    now_iso = _utc_now_iso()

    resolved_review_id = _text(review_id) or _text(source_payload.get("review_id")) or _text(source_payload.get("id")) or str(uuid4())

    resolved_request_id = _text(request_id) or _text(source_payload.get("request_id")) or _text(source_payload.get("scan_id")) or _text(source_payload.get("execution_id"))

    resolved_org_id = _text(organization_id) or _text(org_id) or _text(source_payload.get("organization_id")) or _text(source_payload.get("org_id"))

    resolved_status = _text(status) or _text(source_payload.get("status")) or _STATUS_QUEUED

    resolved_queue_id = _text(queue_id) or _text(source_payload.get("queue_id")) or DEFAULT_QUEUE_ID

    resolved_priority = _int(
        priority if priority is not None else source_payload.get("priority"),
        default=DEFAULT_PRIORITY,
    )

    resolved_attempts = max(
        0,
        _int(attempts if attempts is not None else source_payload.get("attempts"), default=0),
    )
    resolved_max_attempts = max(
        1,
        _int(
            max_attempts if max_attempts is not None else source_payload.get("max_attempts"),
            default=3,
        ),
    )

    resolved_created_at = _text(created_at) or _text(source_payload.get("created_at")) or now_iso
    resolved_updated_at = _text(updated_at) or _text(source_payload.get("updated_at")) or resolved_created_at
    resolved_enqueued_at = _text(enqueued_at) or _text(source_payload.get("enqueued_at")) or resolved_created_at

    return {
        "review_id": resolved_review_id,
        "id": resolved_review_id,
        "request_id": resolved_request_id or None,
        "incident_id": _text(incident_id) or _text(source_payload.get("incident_id")) or None,
        "organization_id": resolved_org_id or None,
        "org_id": resolved_org_id or None,
        "owner_id": _text(owner_id) or _text(source_payload.get("owner_id")) or None,
        "reviewer_id": _text(reviewer_id) or _text(source_payload.get("reviewer_id")) or None,
        "queue_id": resolved_queue_id,
        "source": _text(source) or _text(source_payload.get("source")) or "orchestrator_queue",
        "status": resolved_status,
        "priority": resolved_priority,
        "attempts": resolved_attempts,
        "max_attempts": resolved_max_attempts,
        "available_at": _text(available_at) or _text(source_payload.get("available_at")) or resolved_updated_at,
        "lease_expires_at": _text(lease_expires_at) or _text(source_payload.get("lease_expires_at")) or None,
        "resolution": _text(resolution) or _text(source_payload.get("resolution")) or None,
        "decision": _text(decision) or _text(source_payload.get("decision")) or None,
        "severity": _text(severity) or _text(source_payload.get("severity")) or "medium",
        "notes": _text(notes) or _text(source_payload.get("notes")),
        "tags": _as_list(tags if tags is not None else source_payload.get("tags")),
        "metadata": _merge_metadata(source_payload.get("metadata"), metadata),
        "created_at": resolved_created_at,
        "updated_at": resolved_updated_at,
        "enqueued_at": resolved_enqueued_at,
        "dequeued_at": _text(dequeued_at) or _text(source_payload.get("dequeued_at")) or None,
        "acknowledged_at": _text(acknowledged_at) or _text(source_payload.get("acknowledged_at")) or None,
        "resolved_at": _text(resolved_at) or _text(source_payload.get("resolved_at")) or None,
        "open": _bool(
            source_payload.get("open"),
            default=resolved_status.lower() not in _TERMINAL_STATUSES,
        ),
    }


@dataclass(slots=True)
class ReviewQueue:
    state_store: ReviewStateStore = field(default_factory=build_review_state_store)
    queue_id: str = DEFAULT_QUEUE_ID
    _heap: list[tuple[int, int, str]] = field(default_factory=list, init=False, repr=False)
    _seq: Any = field(default_factory=count, init=False, repr=False)

    @property
    def backend_name(self) -> str:
        return self.state_store.backend_name

    def as_dict(self) -> dict[str, Any]:
        return {
            "queue_id": self.queue_id,
            "backend_name": self.backend_name,
            "ready": True,
        }

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        return bool(self.state_store.healthcheck())

    def recover(self, *, queue_id: str | None = None, limit: int = 10_000) -> dict[str, Any]:
        resolved_queue_id = _text(queue_id) or self.queue_id
        states = self.state_store.list_states(limit=limit, queue_id=resolved_queue_id)
        self._heap.clear()

        recovered = 0
        skipped_terminal = 0

        for state in states:
            status = _text(state.get("status")).lower()
            if status in _TERMINAL_STATUSES or not _bool(
                state.get("open"),
                default=status not in _TERMINAL_STATUSES,
            ):
                skipped_terminal += 1
                continue

            normalized = _normalize_queue_item_payload(state, queue_id=resolved_queue_id)

            if status in {_STATUS_IN_REVIEW, _STATUS_ACKNOWLEDGED}:
                normalized["status"] = _STATUS_QUEUED
                normalized["reviewer_id"] = None
                normalized["lease_expires_at"] = None
                normalized["dequeued_at"] = None
                normalized["updated_at"] = _utc_now_iso()
                self.state_store.update_state(normalized["review_id"], normalized)

            self._push_heap(normalized)
            recovered += 1

        return {
            "queue_id": resolved_queue_id,
            "recovered": recovered,
            "skipped_terminal": skipped_terminal,
            "in_memory_depth": len(self._heap),
        }

    def enqueue(self, payload: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        item = _normalize_queue_item_payload(
            payload,
            queue_id=kwargs.pop("queue_id", None) or self.queue_id,
            status=_STATUS_QUEUED,
            enqueued_at=_utc_now_iso(),
            updated_at=_utc_now_iso(),
            **kwargs,
        )
        persisted = self.state_store.upsert_state(item)
        self._push_heap(persisted)
        return persisted

    def requeue(
        self,
        review_id: str,
        *,
        priority: int | None = None,
        delay_until: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        existing = self.state_store.get_state(review_id)
        if existing is None:
            return None

        updates: dict[str, Any] = {
            "status": _STATUS_QUEUED,
            "open": True,
            "reviewer_id": None,
            "lease_expires_at": None,
            "dequeued_at": None,
            "updated_at": _utc_now_iso(),
        }

        if priority is not None:
            updates["priority"] = _int(priority, default=DEFAULT_PRIORITY)
        if delay_until:
            updates["available_at"] = _text(delay_until)
        if notes:
            updates["notes"] = notes

        updated = self.state_store.update_state(review_id, updates)
        if updated is not None:
            self._push_heap(updated)
        return updated

    def lease_next(self, *, reviewer_id: str | None = None) -> dict[str, Any] | None:
        now_iso = _utc_now_iso()

        while self._heap:
            _, _, review_id = heappop(self._heap)
            state = self.state_store.get_state(review_id)
            if state is None:
                continue

            status = _text(state.get("status")).lower()
            if status in _TERMINAL_STATUSES:
                continue

            if _text(state.get("queue_id"), self.queue_id) != self.queue_id:
                continue

            available_at = _text(state.get("available_at"))
            if available_at and available_at > now_iso:
                self._push_heap(state)
                return None

            leased = self.state_store.update_state(
                review_id,
                {
                    "status": _STATUS_IN_REVIEW,
                    "reviewer_id": _text(reviewer_id) or state.get("reviewer_id"),
                    "dequeued_at": now_iso,
                    "last_seen_at": now_iso,
                    "attempts": _int(state.get("attempts"), default=0) + 1,
                    "updated_at": now_iso,
                    "open": True,
                },
            )
            if leased is not None:
                return leased

        return None

    def acknowledge(self, review_id: str, reviewer_id: str | None = None) -> dict[str, Any] | None:
        return self.state_store.acknowledge(review_id, reviewer_id=reviewer_id)

    def resolve(
        self,
        review_id: str,
        *,
        decision: str = "approved",
        resolution: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        return self.state_store.resolve(
            review_id,
            decision=decision,
            resolution=resolution,
            notes=notes,
        )

    def dismiss(
        self,
        review_id: str,
        *,
        resolution: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        return self.state_store.dismiss(
            review_id,
            resolution=resolution,
            notes=notes,
        )

    def get(self, review_id: str) -> dict[str, Any] | None:
        return self.state_store.get_state(review_id)

    def list_items(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
        open_only: bool | None = None,
    ) -> list[dict[str, Any]]:
        return self.state_store.list_states(
            limit=limit,
            queue_id=self.queue_id,
            status=status,
            open_only=open_only,
        )

    def summarize(self, *, limit: int = 1_000) -> dict[str, Any]:
        summary = self.state_store.summarize(limit=limit)
        summary["queue_id"] = self.queue_id
        summary["in_memory_depth"] = len(self._heap)
        return summary

    def _push_heap(self, item: Mapping[str, Any]) -> None:
        normalized = _normalize_queue_item_payload(item, queue_id=_text(item.get("queue_id")) or self.queue_id)
        heappush(
            self._heap,
            (
                _int(normalized.get("priority"), default=DEFAULT_PRIORITY),
                next(self._seq),
                normalized["review_id"],
            ),
        )


def build_review_queue(
    *,
    state_store: ReviewStateStore | None = None,
    queue_id: str = DEFAULT_QUEUE_ID,
    **store_kwargs: Any,
) -> ReviewQueue:
    resolved_state_store = state_store if state_store is not None else build_review_state_store(**store_kwargs)
    queue = ReviewQueue(state_store=resolved_state_store, queue_id=queue_id)
    queue.recover(queue_id=queue_id)  # persisted item recovery is core queue durability behavior [web:178][web:180]
    return queue


def create_review_queue(
    *,
    state_store: ReviewStateStore | None = None,
    queue_id: str = DEFAULT_QUEUE_ID,
    **store_kwargs: Any,
) -> ReviewQueue:
    return build_review_queue(state_store=state_store, queue_id=queue_id, **store_kwargs)


def get_review_queue(
    *,
    state_store: ReviewStateStore | None = None,
    queue_id: str = DEFAULT_QUEUE_ID,
    **store_kwargs: Any,
) -> ReviewQueue:
    return build_review_queue(state_store=state_store, queue_id=queue_id, **store_kwargs)
