from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

import pytest

from app.orchestrator.reviewqueue import (
    ReviewQueueItem,
    ReviewQueuePriority,
    ReviewQueueStatus,
)
from app.orchestrator.reviewqueueservice import ReviewQueueService


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


def _payload_of(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return result

    if hasattr(result, "as_dict") and callable(result.as_dict):
        payload = result.as_dict()
        assert isinstance(payload, dict)
        return payload

    if hasattr(result, "model_dump") and callable(result.model_dump):
        payload = result.model_dump()
        assert isinstance(payload, dict)
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
        elif isinstance(value, EnumLike):
            payload[name] = str(value.value)
    return payload


def _values(items: Iterable[Any]) -> list[dict[str, Any]]:
    return [_payload_of(item) for item in items]


class EnumLike:
    value: Any


@pytest.fixture()
def service() -> ReviewQueueService:
    return ReviewQueueService()


def test_review_queue_service_can_enqueue_minimal_item(
    service: ReviewQueueService,
) -> None:
    item = service.enqueue(
        source="runtime",
        reason="test-enqueue",
        priority="normal",
    )

    payload = _payload_of(item)
    assert payload.get("id")
    assert payload.get("status") in {"pending", "in_review"}
    assert payload.get("priority")
    assert payload.get("reason") == "test-enqueue"


def test_review_queue_service_accepts_incident_reference_when_provided(
    service: ReviewQueueService,
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
    service: ReviewQueueService,
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
    service: ReviewQueueService,
) -> None:
    service.enqueue(source="runtime", reason="first", priority="normal")
    service.enqueue(source="runtime", reason="second", priority="high")

    items = list(service.list_pending())
    values = _values(items)

    assert values
    for payload in values:
        assert payload.get("status") in {"pending", "in_review"}


def test_review_queue_service_can_mark_item_approved(
    service: ReviewQueueService,
) -> None:
    item = service.enqueue(source="runtime", reason="approve-me", priority="normal")

    updated = service.mark_approved(item_id=item.id)

    payload = _payload_of(updated)
    assert payload.get("status") in {"approved", "resolved"}


def test_review_queue_service_can_mark_item_rejected(
    service: ReviewQueueService,
) -> None:
    item = service.enqueue(source="runtime", reason="reject-me", priority="normal")

    updated = service.mark_rejected(item_id=item.id)

    payload = _payload_of(updated)
    assert payload.get("status") in {"rejected", "resolved"}


def test_review_queue_service_requires_reason_for_enqueue() -> None:
    service = ReviewQueueService()

    with pytest.raises((TypeError, ValueError, AssertionError)):
        service.enqueue(source="runtime", reason="", priority="normal")


def test_review_queue_service_requires_non_blank_source() -> None:
    service = ReviewQueueService()

    with pytest.raises((TypeError, ValueError, AssertionError)):
        service.enqueue(source="", reason="test", priority="normal")


def test_review_queue_service_supports_priority_semantics(
    service: ReviewQueueService,
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
    service: ReviewQueueService,
) -> None:
    item = service.enqueue(source="runtime", reason="json-shape", priority="normal")

    payload = _payload_of(item)
    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_review_queue_service_can_return_item_by_id(
    service: ReviewQueueService,
) -> None:
    created = service.enqueue(source="runtime", reason="lookup", priority="normal")

    found = service.get(item_id=created.id)

    assert found is not None
    assert found.id == created.id


def test_review_queue_service_returns_none_for_unknown_id(
    service: ReviewQueueService,
) -> None:
    result = service.get(item_id="non-existent-id")

    assert result is None


def test_review_queue_service_multiple_enqueues_have_stable_key_sets(
    service: ReviewQueueService,
) -> None:
    first = _payload_of(
        service.enqueue(source="runtime", reason="first", priority="normal")
    )
    second = _payload_of(
        service.enqueue(source="runtime", reason="second", priority="normal")
    )

    assert set(first.keys()) == set(second.keys())


def test_review_queue_service_item_uses_expected_domain_types_when_exposed(
    service: ReviewQueueService,
) -> None:
    item = service.enqueue(source="runtime", reason="typed", priority="normal")

    assert isinstance(item, ReviewQueueItem)
    assert item.status in {
        ReviewQueueStatus.PENDING,
        ReviewQueueStatus.IN_REVIEW,
        "pending",
        "in_review",
    }
    assert item.priority in {
        ReviewQueuePriority.LOW,
        ReviewQueuePriority.NORMAL,
        ReviewQueuePriority.HIGH,
        ReviewQueuePriority.URGENT,
        "low",
        "normal",
        "high",
        "urgent",
    }


def test_review_queue_service_marking_item_preserves_identity(
    service: ReviewQueueService,
) -> None:
    created = service.enqueue(source="runtime", reason="identity", priority="normal")

    approved = service.mark_approved(item_id=created.id)

    assert approved.id == created.id