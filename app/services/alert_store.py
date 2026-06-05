from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import logging
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

from app.services.notification_service import (
    NotificationEngine,
    NotificationEvent,
    build_notification_payload,
    default_channels_for_severity,
)

logger = logging.getLogger(__name__)

AlertChannel = Literal["email", "webhook", "slack"]
AlertEventType = Literal[
    "incident_created",
    "incident_updated",
    "quarantine_created",
    "policy_changed",
]
AlertDeliveryStatus = Literal["active", "paused", "failed"]


_VALID_CHANNELS: frozenset[str] = frozenset({"email", "webhook", "slack"})
_VALID_STATUSES: frozenset[str] = frozenset({"active", "paused", "failed"})
_VALID_EVENTS: frozenset[str] = frozenset(
    {"incident_created", "incident_updated", "quarantine_created", "policy_changed"},
)

# Maps AlertEventType values to NotificationEvent for fan-out
_ALERT_EVENT_TO_NOTIFICATION: dict[str, NotificationEvent] = {
    "incident_created": NotificationEvent.INCIDENT_OPENED,
    "incident_updated": NotificationEvent.INCIDENT_ESCALATED,
    "quarantine_created": NotificationEvent.POLICY_QUARANTINE,
    "policy_changed": NotificationEvent.POLICY_BLOCK,
}

# Maps endpoint mutation operations to NotificationEvent for fan-out
_ENDPOINT_OP_TO_NOTIFICATION: dict[str, NotificationEvent] = {
    "created": NotificationEvent.ALERT_CREATED,
    "updated": NotificationEvent.ALERT_ESCALATED,
    "deleted": NotificationEvent.SYSTEM_HEALTH_DEGRADED,
}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _require_str(value: str, field_name: str) -> str:
    stripped = value.strip() if isinstance(value, str) else ""
    if not stripped:
        raise ValueError(f"{field_name} must be a non-empty string")
    return stripped


def _validate_channel(channel: str) -> AlertChannel:
    if channel not in _VALID_CHANNELS:
        raise ValueError(f"Invalid channel '{channel}'. Must be one of {sorted(_VALID_CHANNELS)}")
    return channel  # type: ignore[return-value]


def _validate_status(status: str) -> AlertDeliveryStatus:
    if status not in _VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of {sorted(_VALID_STATUSES)}")
    return status  # type: ignore[return-value]


def _validate_events(events: list[AlertEventType]) -> list[AlertEventType]:
    invalid = [e for e in events if e not in _VALID_EVENTS]
    if invalid:
        raise ValueError(f"Invalid event type(s): {invalid}. Must be one of {sorted(_VALID_EVENTS)}")
    return events


def _fan_out(
    engine: NotificationEngine | None,
    *,
    operation: str,
    endpoint_id: str,
    channel: str,
    org_id: str | None = None,
) -> None:
    """Fire optional webhook fan-out post-endpoint-mutation. Never raises."""
    if engine is None:
        return
    notification_event = _ENDPOINT_OP_TO_NOTIFICATION.get(operation)
    if notification_event is None:
        return
    try:
        payload = build_notification_payload(
            event=notification_event,
            title=f"IronClaw Alert Endpoint {operation.capitalize()}: {endpoint_id}",
            body=f"Alert endpoint '{endpoint_id}' was {operation} on channel '{channel}'.",
            source_id=endpoint_id,
            source_type="alert_endpoint",
            org_id=org_id,
        )
        resolved_channels = default_channels_for_severity(payload.severity)
        engine.dispatch(payload, resolved_channels)
    except Exception:  # noqa: BLE001
        logger.warning(
            "alert_store | fan_out | suppressed error | op=%s endpoint_id=%s",
            operation,
            endpoint_id,
        )


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


class AlertEndpointStore:
    """In-memory store for alert delivery endpoints (email / webhook / slack).

    Distinct from AlertStore in alertstore.py, which manages security alert
    records. This class manages *notification routing targets* only.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._items: list[AlertEndpointRecord] = []

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_endpoints(
        self,
        *,
        channel: AlertChannel | None = None,
        status: AlertDeliveryStatus | None = None,
    ) -> list[AlertEndpointRecord]:
        with self._lock:
            items = list(self._items)

        if channel is not None:
            if channel not in _VALID_CHANNELS:
                raise ValueError(f"Invalid channel filter '{channel}'")
            items = [item for item in items if item.channel == channel]
        if status is not None:
            if status not in _VALID_STATUSES:
                raise ValueError(f"Invalid status filter '{status}'")
            items = [item for item in items if item.status == status]

        return items

    def list_all(self) -> list[AlertEndpointRecord]:
        """Return all endpoints regardless of channel or status."""
        return self.list_endpoints()

    def get_endpoint(self, endpoint_id: str) -> AlertEndpointRecord | None:
        normalized = endpoint_id.strip() if isinstance(endpoint_id, str) else ""
        if not normalized:
            raise ValueError("endpoint_id must be a non-empty string")
        with self._lock:
            for item in self._items:
                if item.endpoint_id == normalized:
                    return item
        return None

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def create_endpoint(
        self,
        *,
        channel: AlertChannel,
        name: str,
        target: str,
        subscribed_events: list[AlertEventType] | None = None,
        metadata: dict[str, Any] | None = None,
        notification_engine: NotificationEngine | None = None,
        org_id: str | None = None,
    ) -> AlertEndpointRecord:
        validated_channel = _validate_channel(channel)
        validated_name = _require_str(name, "name")
        validated_target = _require_str(target, "target")
        validated_events = _validate_events(list(subscribed_events or []))

        now = _utcnow()
        endpoint = AlertEndpointRecord(
            endpoint_id=f"alert-ep-{uuid4().hex[:12]}",
            channel=validated_channel,
            name=validated_name,
            target=validated_target,
            subscribed_events=validated_events,
            status="active",
            created_at=now,
            updated_at=now,
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._items.append(endpoint)

        _fan_out(
            notification_engine,
            operation="created",
            endpoint_id=endpoint.endpoint_id,
            channel=validated_channel,
            org_id=org_id,
        )
        return endpoint

    def update_endpoint(
        self,
        endpoint_id: str,
        *,
        subscribed_events: list[AlertEventType] | None = None,
        status: AlertDeliveryStatus,
        metadata: dict[str, Any] | None = None,
        notification_engine: NotificationEngine | None = None,
        org_id: str | None = None,
    ) -> AlertEndpointRecord | None:
        validated_status = _validate_status(status)
        validated_events = _validate_events(list(subscribed_events)) if subscribed_events is not None else None

        updated: AlertEndpointRecord | None = None
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
                        validated_events if validated_events is not None else item.subscribed_events,
                    ),
                    status=validated_status,
                    created_at=item.created_at,
                    updated_at=_utcnow(),
                    metadata={
                        **item.metadata,
                        **dict(metadata or {}),
                    },
                )
                self._items[index] = updated
                break

        if updated is not None:
            _fan_out(
                notification_engine,
                operation="updated",
                endpoint_id=updated.endpoint_id,
                channel=updated.channel,
                org_id=org_id,
            )
        return updated

    def delete_endpoint(
        self,
        endpoint_id: str,
        *,
        notification_engine: NotificationEngine | None = None,
        org_id: str | None = None,
    ) -> AlertEndpointRecord | None:
        """Remove an endpoint by ID. Returns the removed record or None if not found."""
        normalized = endpoint_id.strip() if isinstance(endpoint_id, str) else ""
        if not normalized:
            raise ValueError("endpoint_id must be a non-empty string")

        removed: AlertEndpointRecord | None = None
        with self._lock:
            for index, item in enumerate(self._items):
                if item.endpoint_id == normalized:
                    removed = self._items.pop(index)
                    break

        if removed is not None:
            _fan_out(
                notification_engine,
                operation="deleted",
                endpoint_id=removed.endpoint_id,
                channel=removed.channel,
                org_id=org_id,
            )
        return removed

    def reset(self) -> None:
        with self._lock:
            self._items.clear()


# ---------------------------------------------------------------------------
# Module-level singleton — use get_alert_endpoint_store() for DI / testing
# ---------------------------------------------------------------------------


_ALERT_ENDPOINT_STORE = AlertEndpointStore()


def get_alert_endpoint_store() -> AlertEndpointStore:
    """Return the module-level AlertEndpointStore singleton."""
    return _ALERT_ENDPOINT_STORE


def reset_alert_endpoint_store() -> None:
    """Clear all endpoints. Intended for use in tests."""
    _ALERT_ENDPOINT_STORE.reset()
