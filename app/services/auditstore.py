from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.persistencebootstrap import build_store

DEFAULT_AUDIT_TABLE = "audit_events"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_iso8601(value: str | datetime | None) -> str:
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        dt = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat()
    text = str(value).strip()
    return text if text else _utc_now()


def _to_dict(value: Any) -> dict[str, Any]:
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
        return {
            str(key): val
            for key, val in vars(value).items()
            if not str(key).startswith("_") and not callable(val)
        }
    return {"value": value}


def _clean_mapping(value: dict[str, Any] | Mapping[str, Any] | None) -> dict[str, Any]:
    if not value:
        return {}
    return {str(key): item for key, item in dict(value).items() if item is not None}


def _string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _ensure_actor(actor: dict[str, Any] | None, payload: dict[str, Any]) -> dict[str, Any]:
    merged = _clean_mapping(actor)
    for key in ("actor", "actor_id", "actor_type", "actor_name"):
        if key in payload and payload[key] is not None and key not in merged:
            merged[key] = payload[key]
    return merged


def _ensure_target(target: dict[str, Any] | None, payload: dict[str, Any]) -> dict[str, Any]:
    merged = _clean_mapping(target)
    for key in ("target", "target_id", "target_type", "resource_id", "resource_type"):
        if key in payload and payload[key] is not None and key not in merged:
            merged[key] = payload[key]
    return merged


def _ensure_metadata(metadata: dict[str, Any] | None, payload: dict[str, Any]) -> dict[str, Any]:
    explicit = _clean_mapping(metadata)
    reserved = {
        "event_id", "id", "timestamp", "created_at", "occurred_at",
        "action", "event", "event_type", "category", "severity",
        "status", "result", "message", "summary", "description",
        "request_id", "trace_id", "session_id",
        "organization_id", "org_id", "tenant_id", "customer_id",
        "actor", "actor_id", "actor_type", "actor_name",
        "target", "target_id", "target_type", "resource_id", "resource_type",
        "metadata", "details",
    }
    derived = {
        str(key): value
        for key, value in payload.items()
        if key not in reserved and value is not None
    }
    derived.update(explicit)
    return derived


def _normalize_rows(rows: Any) -> list[dict[str, Any]]:
    if rows is None:
        return []
    if isinstance(rows, Mapping):
        return [dict(rows)]
    if isinstance(rows, Iterable) and not isinstance(rows, (str, bytes)):
        return [dict(row) for row in rows]
    return []


# ---------------------------------------------------------------------------
# Payload normalization
# ---------------------------------------------------------------------------

def _normalize_event_payload(
    payload: dict[str, Any] | None = None,
    *,
    event_id: str | None = None,
    action: str | None = None,
    event: str | None = None,
    event_type: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    result: str | None = None,
    message: str | None = None,
    summary: str | None = None,
    description: str | None = None,
    actor: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    session_id: str | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    tenant_id: str | None = None,
    customer_id: str | None = None,
    timestamp: str | datetime | None = None,
    created_at: str | datetime | None = None,
    occurred_at: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source = _clean_mapping(payload or {})
    source.update({key: value for key, value in extra.items() if value is not None})

    resolved_event_id = (
        _string(event_id)
        or _string(source.get("event_id"))
        or _string(source.get("id"))
        or str(uuid4())
    )

    resolved_action = (
        _string(action)
        or _string(event)
        or _string(event_type)
        or _string(source.get("action"))
        or _string(source.get("event"))
        or _string(source.get("event_type"))
    )
    if not resolved_action:
        raise ValueError("action is required")

    resolved_category = (
        _string(category)
        or _string(source.get("category"))
        or "audit"
    )
    resolved_severity = (
        _string(severity)
        or _string(source.get("severity"))
        or "info"
    )
    resolved_status = (
        _string(status)
        or _string(result)
        or _string(source.get("status"))
        or _string(source.get("result"))
        or "success"
    )
    resolved_message = (
        _string(message)
        or _string(summary)
        or _string(description)
        or _string(source.get("message"))
        or _string(source.get("summary"))
        or _string(source.get("description"))
        or resolved_action
    )
    resolved_timestamp = _normalize_iso8601(
        timestamp
        or created_at
        or occurred_at
        or source.get("timestamp")
        or source.get("created_at")
        or source.get("occurred_at")
    )

    resolved_org = (
        _string(organization_id)
        or _string(org_id)
        or _string(tenant_id)
        or _string(customer_id)
        or _string(source.get("organization_id"))
        or _string(source.get("org_id"))
        or _string(source.get("tenant_id"))
        or _string(source.get("customer_id"))
    )
    resolved_request_id = _string(request_id) or _string(source.get("request_id"))
    resolved_trace_id = _string(trace_id) or _string(source.get("trace_id"))
    resolved_session_id = _string(session_id) or _string(source.get("session_id"))

    resolved_actor = _ensure_actor(actor, source)
    resolved_target = _ensure_target(target, source)

    details_payload = _clean_mapping(details) or _clean_mapping(
        _to_dict(source.get("details"))
    )
    metadata_payload = _ensure_metadata(metadata, source)
    if details_payload:
        metadata_payload.setdefault("details", details_payload)

    return {
        "event_id": resolved_event_id,
        "id": resolved_event_id,
        "action": resolved_action,
        "event": resolved_action,
        "event_type": resolved_action,
        "category": resolved_category,
        "severity": resolved_severity,
        "status": resolved_status,
        "result": resolved_status,
        "message": resolved_message,
        "summary": resolved_message,
        "description": resolved_message,
        "timestamp": resolved_timestamp,
        "created_at": resolved_timestamp,
        "occurred_at": resolved_timestamp,
        "actor": resolved_actor,
        "target": resolved_target,
        "metadata": metadata_payload,
        "details": details_payload or metadata_payload.get("details", {}),
        "request_id": resolved_request_id or None,
        "trace_id": resolved_trace_id or None,
        "session_id": resolved_session_id or None,
        "organization_id": resolved_org or None,
        "org_id": resolved_org or None,
        "tenant_id": resolved_org or None,
        "customer_id": resolved_org or None,
    }


# ---------------------------------------------------------------------------
# AuditStore — persistence-backed structured audit event store
#
# Distinct from SecurityAuditEventStore (audit_store.py) which is the
# in-memory store for raw IronClaw security runtime events with seeded
# defaults and thread-safe access.
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class AuditStore:
    """
    Persistence-backed store for structured audit events.

    Uses the build_store backend (Supabase or in-memory depending on
    environment). For in-memory seeded security runtime events, use
    SecurityAuditEventStore from audit_store.py.
    """

    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_AUDIT_TABLE

    @property
    def backend_name(self) -> str:
        return str(getattr(self.backend, "backend_name", "memory"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "table_name": self.table_name,
            "ready": self.is_ready(),
        }

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        health = getattr(self.backend, "healthcheck", None)
        if callable(health):
            try:
                return bool(health())
            except Exception:
                return False
        return True

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def log_event(
        self, payload: dict[str, Any] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        event = _normalize_event_payload(payload, **kwargs)
        insert = getattr(self.backend, "insert", None)
        if not callable(insert):
            return event
        inserted = insert(self.table_name, event)
        if isinstance(inserted, dict):
            return dict(inserted)
        if isinstance(inserted, list) and inserted:
            return dict(inserted[0])
        return event

    def create_event(
        self, payload: dict[str, Any] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        return self.log_event(payload, **kwargs)

    def write_event(
        self, payload: dict[str, Any] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        return self.log_event(payload, **kwargs)

    def append(
        self, payload: dict[str, Any] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        return self.log_event(payload, **kwargs)

    def record(
        self,
        action: str,
        *,
        actor: dict[str, Any] | None = None,
        target: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: str = "info",
        status: str = "success",
        message: str | None = None,
        organization_id: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        session_id: str | None = None,
        timestamp: str | datetime | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self.log_event(
            None,
            action=action,
            actor=actor,
            target=target,
            metadata=metadata,
            severity=severity,
            status=status,
            message=message,
            organization_id=organization_id,
            request_id=request_id,
            trace_id=trace_id,
            session_id=session_id,
            timestamp=timestamp,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_events(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        organization_id: str | None = None,
        actor_id: str | None = None,
        action: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query_filters = _clean_mapping(filters)
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if action:
            query_filters.setdefault("action", action)
        if severity:
            query_filters.setdefault("severity", severity)
        if status:
            query_filters.setdefault("status", status)
        if session_id:
            query_filters.setdefault("session_id", session_id)
        if request_id:
            query_filters.setdefault("request_id", request_id)
        if trace_id:
            query_filters.setdefault("trace_id", trace_id)

        select = getattr(self.backend, "select", None)
        if not callable(select):
            return []

        rows = _normalize_rows(
            select(self.table_name, limit=limit, filters=query_filters or None)
        )
        results = [dict(row) for row in rows]

        if actor_id:
            normalized_actor_id = _string(actor_id)
            filtered: list[dict[str, Any]] = []
            for row in results:
                actor = _to_dict(row.get("actor"))
                row_actor_id = _string(actor.get("actor_id") or actor.get("id"))
                # also check flat actor_id field for backends that store it flat
                flat_actor_id = _string(row.get("actor_id"))
                if normalized_actor_id in (row_actor_id, flat_actor_id):
                    filtered.append(row)
            results = filtered

        results.sort(
            key=lambda row: _string(
                row.get("timestamp") or row.get("created_at") or row.get("occurred_at")
            ),
            reverse=True,
        )
        return results

    def query(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_events(**kwargs)

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        normalized_id = _string(event_id)
        if not normalized_id:
            raise ValueError("event_id is required")

        select = getattr(self.backend, "select", None)
        if not callable(select):
            return None

        for key in ("event_id", "id"):
            rows = _normalize_rows(
                select(self.table_name, filters={key: normalized_id}, limit=1)
            )
            if rows:
                return dict(rows[0])
        return None

    def find_event(self, event_id: str) -> dict[str, Any] | None:
        return self.get_event(event_id)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_event(self, event_id: str) -> dict[str, Any] | None:
        normalized_id = _string(event_id)
        if not normalized_id:
            raise ValueError("event_id is required")

        delete = getattr(self.backend, "delete", None)
        if not callable(delete):
            return None

        for key in ("event_id", "id"):
            deleted = delete(self.table_name, filters={key: normalized_id})
            rows = _normalize_rows(deleted)
            if rows:
                return dict(rows[0])
        return None

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def summarize(
        self,
        *,
        limit: int = 1000,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        rows = self.list_events(limit=limit, organization_id=organization_id)
        by_action: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for row in rows:
            action = _string(row.get("action"), "unknown")
            severity = _string(row.get("severity"), "unknown")
            status = _string(row.get("status"), "unknown")
            category = _string(row.get("category"), "unknown")
            by_action[action] = by_action.get(action, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1

        return {
            "total": len(rows),
            "by_action": by_action,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_category": by_category,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def build_audit_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_AUDIT_TABLE,
    **store_kwargs: Any,
) -> AuditStore:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return AuditStore(backend=resolved_backend, table_name=table_name)


def create_audit_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_AUDIT_TABLE,
    **store_kwargs: Any,
) -> AuditStore:
    return build_audit_store(backend=backend, table_name=table_name, **store_kwargs)


def get_audit_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_AUDIT_TABLE,
    **store_kwargs: Any,
) -> AuditStore:
    return build_audit_store(backend=backend, table_name=table_name, **store_kwargs)