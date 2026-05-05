from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Literal
from uuid import uuid4


AlertChannel = Literal["email", "webhook", "slack"]
AlertEventType = Literal[
    "incident_created",
    "incident_updated",
    "quarantine_created",
    "policy_changed",
]
AlertDeliveryStatus = Literal["active", "paused", "failed"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class AlertEndpointRecord:
    endpoint_id: str
    channel: AlertChannel
    name: str
    target: str
    subscribed_events: list[AlertEventType]
    status: AlertDeliveryStatus
    created_at: datetime
    updated_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        payload["updated_at"] = self.updated_at.isoformat().replace("+00:00", "Z")
        return payload


class AlertStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._items: list[AlertEndpointRecord] = []

    def list_endpoints(
        self,
        *,
        channel: AlertChannel | None = None,
        status: AlertDeliveryStatus | None = None,
    ) -> list[AlertEndpointRecord]:
        with self._lock:
            items = list(self._items)

        if channel is not None:
            items = [item for item in items if item.channel == channel]
        if status is not None:
            items = [item for item in items if item.status == status]

        return items

    def get_endpoint(self, endpoint_id: str) -> AlertEndpointRecord | None:
        with self._lock:
            for item in self._items:
                if item.endpoint_id == endpoint_id:
                    return item
        return None

    def create_endpoint(
        self,
        *,
        channel: AlertChannel,
        name: str,
        target: str,
        subscribed_events: list[AlertEventType] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AlertEndpointRecord:
        now = _utcnow()
        endpoint = AlertEndpointRecord(
            endpoint_id=f"alert-{uuid4().hex[:12]}",
            channel=channel,
            name=name.strip(),
            target=target.strip(),
            subscribed_events=list(subscribed_events or []),
            status="active",
            created_at=now,
            updated_at=now,
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._items.append(endpoint)

        return endpoint

    def update_endpoint(
        self,
        endpoint_id: str,
        *,
        subscribed_events: list[AlertEventType] | None = None,
        status: AlertDeliveryStatus,
        metadata: dict[str, Any] | None = None,
    ) -> AlertEndpointRecord | None:
        with self._lock:
            for index, item in enumerate(self._items):
                if item.endpoint_id != endpoint_id:
                    continue

                updated = AlertEndpointRecord(
                    endpoint_id=item.endpoint_id,
                    channel=item.channel,
                    name=item.name,
                    target=item.target,
                    subscribed_events=list(
                        subscribed_events if subscribed_events is not None else item.subscribed_events
                    ),
                    status=status,
                    created_at=item.created_at,
                    updated_at=_utcnow(),
                    metadata={
                        **item.metadata,
                        **dict(metadata or {}),
                    },
                )
                self._items[index] = updated
                return updated

        return None

    def reset(self) -> None:
        with self._lock:
            self._items.clear()


_ALERT_STORE = AlertStore()


def get_alert_store() -> AlertStore:
    return _ALERT_STORE


def reset_alert_store() -> None:
    _ALERT_STORE.reset()