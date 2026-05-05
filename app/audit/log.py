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
    if isinstance(value, (int, float)):
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
class AuditActor:
    actor_id: str
    actor_type: str
    display_name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "actor_type": self.actor_type,
            "display_name": self.display_name,
        }


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    event_type: str
    severity: str
    action: str
    result: str
    resource: str
    message: str
    actor: AuditActor
    created_at: datetime
    request_id: str = ""
    org_id: str = ""
    trace_id: str = ""
    requires_review: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "action": self.action,
            "result": self.result,
            "resource": self.resource,
            "message": self.message,
            "actor": self.actor.to_dict(),
            "created_at": _isoformat(self.created_at),
            "request_id": self.request_id,
            "org_id": self.org_id,
            "trace_id": self.trace_id,
            "requires_review": self.requires_review,
        }


@dataclass(frozen=True, slots=True)
class AuditLog:
    service: str = "ironclaw-security"
    environment: str = "local"
    total_events: int = 0
    critical_events: int = 0
    warning_events: int = 0
    review_required_events: int = 0
    events: tuple[AuditEvent, ...] = ()
    checked_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "environment": self.environment,
            "total_events": self.total_events,
            "critical_events": self.critical_events,
            "warning_events": self.warning_events,
            "review_required_events": self.review_required_events,
            "events": [item.to_dict() for item in self.events],
            "checked_at": _isoformat(self.checked_at),
        }


def _normalize_actor(value: Any) -> AuditActor:
    if not isinstance(value, dict):
        return AuditActor(actor_id="", actor_type="system", display_name="System")

    return AuditActor(
        actor_id=_coerce_str(value.get("actor_id")),
        actor_type=_coerce_str(value.get("actor_type"), "system") or "system",
        display_name=_coerce_str(value.get("display_name"), "System") or "System",
    )


def _normalize_event(value: Any) -> AuditEvent | None:
    if not isinstance(value, dict):
        return None

    event_id = _coerce_str(value.get("event_id"))
    event_type = _coerce_str(value.get("event_type"))
    if not event_id and not event_type:
        return None

    return AuditEvent(
        event_id=event_id or "audit-event",
        event_type=event_type or "audit.event",
        severity=_coerce_str(value.get("severity"), "info") or "info",
        action=_coerce_str(value.get("action"), "observe") or "observe",
        result=_coerce_str(value.get("result"), "success") or "success",
        resource=_coerce_str(value.get("resource"), "system") or "system",
        message=_coerce_str(value.get("message"), "Audit event recorded.") or "Audit event recorded.",
        actor=_normalize_actor(value.get("actor")),
        created_at=_coerce_datetime(value.get("created_at"), _utc_now()) or _utc_now(),
        request_id=_coerce_str(value.get("request_id")),
        org_id=_coerce_str(value.get("org_id")),
        trace_id=_coerce_str(value.get("trace_id")),
        requires_review=_coerce_bool(value.get("requires_review"), False),
    )


def default_audit_log() -> AuditLog:
    return AuditLog()


def build_audit_log(
    data: dict[str, Any] | None = None,
    *,
    baseline: AuditLog | None = None,
) -> AuditLog:
    source = data or {}
    current = baseline or default_audit_log()

    raw_events = source.get("events")
    if isinstance(raw_events, list):
        events = tuple(item for entry in raw_events if (item := _normalize_event(entry)) is not None)
    else:
        events = current.events

    total_events = max(0, _coerce_int(source.get("total_events"), current.total_events or len(events)))
    critical_events = max(0, _coerce_int(source.get("critical_events"), current.critical_events))
    warning_events = max(0, _coerce_int(source.get("warning_events"), current.warning_events))
    review_required_events = max(0, _coerce_int(source.get("review_required_events"), current.review_required_events))

    if not source.get("total_events") and events:
        total_events = len(events)
    if not source.get("critical_events") and events:
        critical_events = sum(1 for item in events if item.severity.lower() == "critical")
    if not source.get("warning_events") and events:
        warning_events = sum(1 for item in events if item.severity.lower() in {"warning", "warn"})
    if not source.get("review_required_events") and events:
        review_required_events = sum(1 for item in events if item.requires_review)

    return AuditLog(
        service=_coerce_str(source.get("service"), current.service) or current.service,
        environment=_coerce_str(source.get("environment"), current.environment) or current.environment,
        total_events=total_events,
        critical_events=critical_events,
        warning_events=warning_events,
        review_required_events=review_required_events,
        events=events,
        checked_at=_coerce_datetime(source.get("checked_at"), _utc_now()) or _utc_now(),
    )


def audit_log_summary(log: AuditLog) -> dict[str, Any]:
    denied_events = sum(1 for item in log.events if item.result.lower() in {"denied", "blocked", "quarantined"})
    human_actor_events = sum(1 for item in log.events if item.actor.actor_type.lower() in {"human", "operator", "analyst"})

    return {
        "service": log.service,
        "environment": log.environment,
        "counts": {
            "total_events": log.total_events,
            "critical_events": log.critical_events,
            "warning_events": log.warning_events,
            "review_required_events": log.review_required_events,
            "denied_events": denied_events,
            "human_actor_events": human_actor_events,
        },
        "events": [item.to_dict() for item in log.events],
        "checked_at": _isoformat(log.checked_at),
    }