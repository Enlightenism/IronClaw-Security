from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from typing import Any
from uuid import uuid4


class AuditSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class IntegrationAuditEvent:
    event_id: str
    integration_id: str
    event_type: str
    severity: AuditSeverity
    occurred_at: datetime
    message: str
    actor: str = "system"
    adapter_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    content_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "integration_id": self.integration_id,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "occurred_at": self.occurred_at.isoformat(),
            "message": self.message,
            "actor": self.actor,
            "adapter_id": self.adapter_id,
            "metadata": _normalize_mapping(self.metadata),
            "content_hash": self.content_hash,
        }


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _normalize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _normalize_value(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list | tuple):
        return [_normalize_value(item) for item in value]
    return value


def _normalize_mapping(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {str(k): _normalize_value(v) for k, v in sorted(metadata.items(), key=lambda item: str(item[0]))}


def _build_content_hash(payload: Mapping[str, Any]) -> str:
    canonical = repr(_normalize_mapping(payload)).encode("utf-8")
    return sha256(canonical).hexdigest()


def create_audit_event(
    *,
    integration_id: str,
    event_type: str,
    severity: AuditSeverity,
    message: str,
    actor: str = "system",
    adapter_id: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> IntegrationAuditEvent:
    timestamp = occurred_at or _utcnow()
    normalized_metadata = _normalize_mapping(metadata or {})
    hash_payload = {
        "integration_id": integration_id,
        "event_type": event_type,
        "severity": severity.value,
        "occurred_at": timestamp.isoformat(),
        "message": message,
        "actor": actor,
        "adapter_id": adapter_id,
        "metadata": normalized_metadata,
    }

    return IntegrationAuditEvent(
        event_id=str(uuid4()),
        integration_id=integration_id,
        event_type=event_type,
        severity=severity,
        occurred_at=timestamp,
        message=message,
        actor=actor,
        adapter_id=adapter_id,
        metadata=normalized_metadata,
        content_hash=_build_content_hash(hash_payload),
    )


def adapter_evaluated_event(
    *,
    integration_id: str,
    adapter_id: str,
    runtime_family: str,
    version: str,
    state: str,
    reason: str,
    actor: str = "system",
) -> IntegrationAuditEvent:
    severity = AuditSeverity.ERROR if state == "unsupported" else (AuditSeverity.WARNING if state == "warning" else AuditSeverity.INFO)
    return create_audit_event(
        integration_id=integration_id,
        event_type="adapter.evaluated",
        severity=severity,
        message=f"Adapter {adapter_id} evaluated as {state}.",
        actor=actor,
        adapter_id=adapter_id,
        metadata={
            "runtime_family": runtime_family,
            "version": version,
            "state": state,
            "reason": reason,
        },
    )


def summary_generated_event(
    *,
    integration_id: str,
    overall_state: str,
    risk_score: float,
    total_adapters: int,
    actor: str = "system",
) -> IntegrationAuditEvent:
    severity = AuditSeverity.ERROR if overall_state == "unsupported" else (AuditSeverity.WARNING if overall_state == "warning" else AuditSeverity.INFO)
    return create_audit_event(
        integration_id=integration_id,
        event_type="integration.summary_generated",
        severity=severity,
        message=f"Integration summary generated with state={overall_state}.",
        actor=actor,
        metadata={
            "overall_state": overall_state,
            "risk_score": risk_score,
            "total_adapters": total_adapters,
        },
    )


def state_changed_event(
    *,
    integration_id: str,
    previous_state: str,
    new_state: str,
    actor: str = "system",
    reason: str = "",
) -> IntegrationAuditEvent:
    severity = AuditSeverity.ERROR if new_state == "unsupported" else (AuditSeverity.WARNING if new_state == "warning" else AuditSeverity.INFO)
    return create_audit_event(
        integration_id=integration_id,
        event_type="integration.state_changed",
        severity=severity,
        message=f"Integration state changed from {previous_state} to {new_state}.",
        actor=actor,
        metadata={
            "previous_state": previous_state,
            "new_state": new_state,
            "reason": reason,
        },
    )


def filter_audit_events(
    events: Iterable[IntegrationAuditEvent],
    *,
    integration_id: str | None = None,
    event_type: str | None = None,
    severity: AuditSeverity | None = None,
    actor: str | None = None,
    adapter_id: str | None = None,
) -> list[IntegrationAuditEvent]:
    filtered: list[IntegrationAuditEvent] = []

    for event in events:
        if integration_id is not None and event.integration_id != integration_id:
            continue
        if event_type is not None and event.event_type != event_type:
            continue
        if severity is not None and event.severity != severity:
            continue
        if actor is not None and event.actor != actor:
            continue
        if adapter_id is not None and event.adapter_id != adapter_id:
            continue
        filtered.append(event)

    return filtered


def sort_audit_events(
    events: Iterable[IntegrationAuditEvent],
    *,
    descending: bool = False,
) -> list[IntegrationAuditEvent]:
    return sorted(events, key=lambda event: event.occurred_at, reverse=descending)


def serialize_audit_events(events: Iterable[IntegrationAuditEvent]) -> list[dict[str, Any]]:
    return [event.to_dict() for event in events]
