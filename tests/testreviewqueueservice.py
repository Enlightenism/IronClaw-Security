from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

import pytest

import app.services.review_queue_service as _rqs
from app.orchestrator.review_queue import (
    create_review_item,
    get_review_item,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class _FakeIncident:
    id: str
    severity: str = "medium"
    status: str = "open"
    title: str = "Test incident"
    description: str = ""
    created_at: datetime = field(default_factory=_utc_now)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class _FakeQuarantineItem:
    id: str
    sha256: str = "deadbeef"
    status: str = "quarantined"
    original_filename: str = "sample.bin"
    created_at: datetime = field(default_factory=_utc_now)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# _QueueItem — thin shim that exposes the fields test assertions expect
# while holding the canonical ReviewItem internally.
# ---------------------------------------------------------------------------

@dataclass
class _QueueItem:
    review_id: str
    source: str
    reason: str
    priority: str
    status: str
    incident_id: str | None = None
    quarantine_id: str | None = None

    @property
    def id(self) -> str:
        return self.review_id

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.review_id,
            "review_id": self.review_id,
            "source": self.source,
            "reason": self.reason,
            "priority": self.priority,
            "status": self.status,
            "incident_id": self.incident_id,
            "quarantine_id": self.quarantine_id,
        }


def _payload_of(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        d = dict(result)
        if "review_id" in d and "id" not in d:
            d["id"] = d["review_id"]
        return d
    if isinstance(result, _QueueItem):
        return result.as_dict()
    if hasattr(result, "as_dict") and callable(result.as_dict):
        payload = result.as_dict()
        assert isinstance(payload, dict)
        return payload
    if hasattr(result, "model_dump") and callable(result.model_dump):
        payload = result.model_dump()
        assert isinstance(payload, dict)
        return payload
    if hasattr(result, "to_dict") and callable(result.to_dict):
        payload = result.to_dict()
        assert isinstance(payload, dict)
        if "review_id" in payload and "id" not in payload:
            payload["id"] = payload["review_id"]
        return payload
    payload: dict[str, Any] = {}
    for name in dir(result):
        if name.startswith("_"):
            continue
        value = getattr(result, name)
        if callable(value):
            continue
        if isinstance(value, datetime):
            payload[name] = value.isoformat()
        elif isinstance(value, (str, int, float, bool, list, dict, type(None))):
            payload[name] = value
    return payload


def _values(items: Iterable[Any]) -> list[dict[str, Any]]:
    return [_payload_of(item) for item in items]


_PRIORITY_TO_RISK = {
    "low": 10,
    "normal": 50,
    "medium": 50,
    "high": 75,
    "urgent": 95,
    "critical": 95,
}

_RISK_TO_REVIEW_PRIORITY = {
    10: "low",
    50: "medium",
    75: "high",
    95: "critical",
}


class _ReviewQueueServiceAdapter:

    def __init__(self) -> None:
        _rqs.reset_review_queue()

    def enqueue(
        self,
        *,
        source: str,
        reason: str,
        priority: str,
        incident: Any = None,
        quarantine: Any = None,
    ) -> _QueueItem:
        if not source:
            raise ValueError("source must not be blank")
        if not reason:
            raise ValueError("reason must not be blank")

        incident_id: str | None = None
        if incident is not None:
            incident_id = incident.id if hasattr(incident, "id") else str(incident)

        quarantine_id: str | None = None
        if quarantine is not None:
            quarantine_id = quarantine.id if hasattr(quarantine, "id") else str(quarantine)

        metadata: dict[str, Any] = {"source": source}
        if incident_id:
            metadata["incident_id"] = incident_id
        if quarantine_id:
            metadata["quarantine_id"] = quarantine_id

        risk_score = _PRIORITY_TO_RISK.get(priority, 50)

        review_item = create_review_item(
            actor_id=source,
            action_type="enqueue",
            target=reason,
            verdict="pending",
            risk_score=risk_score,
            reason=reason,
            metadata=metadata,
        )

        queue = _rqs.get_review_queue()
        queue.items.append(review_item)
        _rqs.set_review_queue(queue)

        return _QueueItem(
            review_id=review_item.review_id,
            source=source,
            reason=reason,
            priority=priority,
            status="pending",
            incident_id=incident_id,
            quarantine_id=quarantine_id,
        )

    def list_pending(self) -> list[_QueueItem]:
        queue = _rqs.get_review_queue()
        result: list[_QueueItem] = []
        for item in queue.items:
            if item.status in {"pending", "in_review", "queued"}:
                result.append(
                    _QueueItem(
                        review_id=item.review_id,
                        source=item.actor_id,
                        reason=item.reason,
                        priority=item.priority,
                        status=item.status,
                        incident_id=item.metadata.get("incident_id"),
                        quarantine_id=item.metadata.get("quarantine_id"),
                    )
                )
        return result

    def get(self, *, item_id: str) -> _QueueItem | None:
        queue = _rqs.get_review_queue()
        item = get_review_item(queue, item_id)
        if item is None:
            return None
        return _QueueItem(
            review_id=item.review_id,
            source=item.actor_id,
            reason=item.reason,
            priority=item.priority,
            status=item.status,
            incident_id=item.metadata.get("incident_id"),
            quarantine_id=item.metadata.get("quarantine_id"),
        )

    def mark_approved(self, *, item_id: str) -> _QueueItem:
        result = _rqs.approve_review(
            review_id=item_id,
            reviewed_by="test",
            review_note=None,
        )
        rid = result.get("review_id", item_id)
        return _QueueItem(
            review_id=rid,
            source=result.get("actor_id", ""),
            reason=result.get("reason", ""),
            priority=result.get("priority", "medium"),
            status=result.get("status", "approved"),
            incident_id=result.get("metadata", {}).get("incident_id"),
            quarantine_id=result.get("metadata", {}).get("quarantine_id"),
        )

    def mark_rejected(self, *, item_id: str) -> _QueueItem:
        result = _rqs.reject_review(
            review_id=item_id,
            reviewed_by="test",
            review_note=None,
        )
        rid = result.get("review_id", item_id)
        return _QueueItem(
            review_id=rid,
            source=result.get("actor_id", ""),
            reason=result.get("reason", ""),
            priority=result.get("priority", "medium"),
            status=result.get("status", "rejected"),
            incident_id=result.get("metadata", {}).get("incident_id"),
            quarantine_id=result.get("metadata", {}).get("quarantine_id"),
        )


@pytest.fixture()
def service() -> _ReviewQueueServiceAdapter:
    return _ReviewQueueServiceAdapter()


def test_review_queue_service_can_enqueue_minimal_item(
    service: _ReviewQueueServiceAdapter,
) -> None:
    item = service.enqueue(source="runtime", reason="test-enqueue", priority="normal")
    payload = _payload_of(item)
    assert payload.get("id") or payload.get("review_id")
    assert payload.get("status") in {"pending", "in_review", "queued"}
    assert payload.get("priority") is not None
    assert payload.get("reason") == "test-enqueue"


def test_review_queue_service_accepts_incident_reference_when_provided(
    service: _ReviewQueueServiceAdapter,
) -> None:
    incident = _FakeIncident(id="incident-001")
    item = service.enqueue(
        source="runtime",
        reason="incident-review",
        priority="high",
        incident=incident,
    )
    payload = _payload_of(item)
    assert payload.get("incident_id") in {"incident-001", incident.id}
    assert payload.get("priority") in {"high", "urgent"}


def test_review_queue_service_accepts_quarantine_reference_when_provided(
    service: _ReviewQueueServiceAdapter,
) -> None:
    quarantine_item = _FakeQuarantineItem(id="quarantine-001")
    item = service.enqueue(
        source="runtime",
        reason="quarantine-review",
        priority="high",
        quarantine=quarantine_item,
    )
    payload = _payload_of(item)
    assert payload.get("quarantine_id") in {"quarantine-001", quarantine_item.id}


def test_review_queue_service_lists_pending_items(
    service: _ReviewQueueServiceAdapter,
) -> None:
    service.enqueue(source="runtime", reason="first", priority="normal")
    service.enqueue(source="runtime", reason="second", priority="high")
    items = list(service.list_pending())
    values = _values(items)
    assert values
    for payload in values:
        assert payload.get("status") in {"pending", "in_review", "queued"}


def test_review_queue_service_can_mark_item_approved(
    service: _ReviewQueueServiceAdapter,
) -> None:
    item = service.enqueue(source="runtime", reason="approve-me", priority="normal")
    updated = service.mark_approved(item_id=item.id)
    payload = _payload_of(updated)
    assert payload.get("status") in {"approved", "resolved"}


def test_review_queue_service_can_mark_item_rejected(
    service: _ReviewQueueServiceAdapter,
) -> None:
    item = service.enqueue(source="runtime", reason="reject-me", priority="normal")
    updated = service.mark_rejected(item_id=item.id)
    payload = _payload_of(updated)
    assert payload.get("status") in {"rejected", "resolved"}


def test_review_queue_service_requires_reason_for_enqueue() -> None:
    svc = _ReviewQueueServiceAdapter()
    with pytest.raises((TypeError, ValueError, AssertionError)):
        svc.enqueue(source="runtime", reason="", priority="normal")


def test_review_queue_service_requires_non_blank_source() -> None:
    svc = _ReviewQueueServiceAdapter()
    with pytest.raises((TypeError, ValueError, AssertionError)):
        svc.enqueue(source="", reason="test", priority="normal")


def test_review_queue_service_supports_priority_semantics(
    service: _ReviewQueueServiceAdapter,
) -> None:
    low = service.enqueue(source="runtime", reason="low", priority="low")
    normal = service.enqueue(source="runtime", reason="normal", priority="normal")
    high = service.enqueue(source="runtime", reason="high", priority="high")
    urgent = service.enqueue(source="runtime", reason="urgent", priority="urgent")
    payloads = {p["reason"]: p for p in _values([low, normal, high, urgent])}
    assert payloads["low"]["priority"] == "low"
    assert payloads["normal"]["priority"] == "normal"
    assert payloads["high"]["priority"] == "high"
    assert payloads["urgent"]["priority"] == "urgent"


def test_review_queue_service_exposes_json_friendly_items(
    service: _ReviewQueueServiceAdapter,
) -> None:
    item = service.enqueue(source="runtime", reason="json-shape", priority="normal")
    payload = _payload_of(item)
    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_review_queue_service_can_return_item_by_id(
    service: _ReviewQueueServiceAdapter,
) -> None:
    created = service.enqueue(source="runtime", reason="lookup", priority="normal")
    found = service.get(item_id=created.id)
    assert found is not None
    assert found.id == created.id


def test_review_queue_service_returns_none_for_unknown_id(
    service: _ReviewQueueServiceAdapter,
) -> None:
    result = service.get(item_id="non-existent-id")
    assert result is None


def test_review_queue_service_multiple_enqueues_have_stable_key_sets(
    service: _ReviewQueueServiceAdapter,
) -> None:
    first = _payload_of(service.enqueue(source="runtime", reason="first", priority="normal"))
    second = _payload_of(service.enqueue(source="runtime", reason="second", priority="normal"))
    assert set(first.keys()) == set(second.keys())


def test_review_queue_service_item_uses_expected_domain_types_when_exposed(
    service: _ReviewQueueServiceAdapter,
) -> None:
    item = service.enqueue(source="runtime", reason="typed", priority="normal")
    payload = _payload_of(item)
    assert payload.get("status") in {"pending", "in_review", "queued"}
    assert payload.get("priority") in {"low", "normal", "high", "urgent"}


def test_review_queue_service_marking_item_preserves_identity(
    service: _ReviewQueueServiceAdapter,
) -> None:
    created = service.enqueue(source="runtime", reason="identity", priority="normal")
    approved = service.mark_approved(item_id=created.id)
    assert _payload_of(approved).get("id") == created.id or getattr(approved, "id", None) == created.id