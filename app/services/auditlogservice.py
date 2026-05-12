from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.persistencebootstrap import build_store

DEFAULT_AUDIT_LOG_TABLE = "audit_logs"

_AUDIT_ACTION_FALLBACK = "unknown"
_AUDIT_ACTOR_TYPE_FALLBACK = "system"
_AUDIT_RESULT_FALLBACK = "success"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_timestamp(value: str | datetime | None) -> str:
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        dt = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat()
    text = str(value).strip()
    return text or _utc_now()


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
    if isinstance(value, Mapping):  # Mapping broadens accepted mapping-like inputs [web:115]
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


def _normalize_result(value: Any) -> str:
    normalized = _string(value, _AUDIT_RESULT_FALLBACK).lower()
    if normalized in {"ok", "passed"}:
        return "success"
    if normalized in {"fail", "failed"}:
        return "failure"
    if normalized in {"success", "failure", "denied", "error"}:
        return normalized
    return _AUDIT_RESULT_FALLBACK


def _normalize_audit_log_payload(
    payload: dict[str, Any] | None = None,
    *,
    log_id: str | None = None,
    action: str | None = None,
    event_type: str | None = None,
    category: str | None = None,
    actor_id: str | None = None,
    actor_type: str | None = None,
    actor_email: str | None = None,
    owner_id: str | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    customer_id: str | None = None,
    resource_id: str | None = None,
    resource_type: str | None = None,
    target_id: str | None = None,
    target_type: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    session_id: str | None = None,
    incident_id: str | None = None,
    review_id: str | None = None,
    scan_id: str | None = None,
    result: str | None = None,
    outcome: str | None = None,
    source: str | None = None,
    message: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: dict[str, Any] | None = None,
    changes: dict[str, Any] | None = None,
    tags: list[Any] | None = None,
    created_at: str | datetime | None = None,
    occurred_at: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _mapping(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    resolved_log_id = (
        _string(log_id)
        or _string(source_payload.get("log_id"))
        or _string(source_payload.get("audit_id"))
        or _string(source_payload.get("id"))
        or str(uuid4())
    )

    resolved_action = (
        _string(action)
        or _string(event_type)
        or _string(source_payload.get("action"))
        or _string(source_payload.get("event_type"))
        or _AUDIT_ACTION_FALLBACK
    )

    resolved_category = (
        _string(category)
        or _string(source_payload.get("category"))
        or "audit"
    )

    resolved_actor_type = (
        _string(actor_type)
        or _string(source_payload.get("actor_type"))
        or _AUDIT_ACTOR_TYPE_FALLBACK
    )

    resolved_org = (
        _string(organization_id)
        or _string(org_id)
        or _string(customer_id)
        or _string(source_payload.get("organization_id"))
        or _string(source_payload.get("org_id"))
        or _string(source_payload.get("customer_id"))
    )

    resolved_result = _normalize_result(
        result
        or outcome
        or source_payload.get("result")
        or source_payload.get("outcome")
    )

    resolved_source = (
        _string(source)
        or _string(source_payload.get("source"))
        or "ironclaw"
    )

    resolved_created_at = _normalize_timestamp(
        created_at or source_payload.get("created_at") or occurred_at or source_payload.get("occurred_at")
    )
    resolved_occurred_at = _normalize_timestamp(
        occurred_at or source_payload.get("occurred_at") or resolved_created_at
    )

    return {
        "log_id": resolved_log_id,
        "audit_id": resolved_log_id,
        "id": resolved_log_id,
        "action": resolved_action,
        "event_type": resolved_action,
        "category": resolved_category,
        "actor_id": _string(actor_id) or _string(source_payload.get("actor_id")) or None,
        "actor_type": resolved_actor_type,
        "actor_email": _string(actor_email) or _string(source_payload.get("actor_email")) or None,
        "owner_id": _string(owner_id) or _string(source_payload.get("owner_id")) or None,
        "organization_id": resolved_org or None,
        "org_id": resolved_org or None,
        "customer_id": resolved_org or None,
        "resource_id": _string(resource_id) or _string(source_payload.get("resource_id")) or None,
        "resource_type": _string(resource_type) or _string(source_payload.get("resource_type")) or None,
        "target_id": _string(target_id) or _string(source_payload.get("target_id")) or None,
        "target_type": _string(target_type) or _string(source_payload.get("target_type")) or None,
        "request_id": _string(request_id) or _string(source_payload.get("request_id")) or None,
        "trace_id": _string(trace_id) or _string(source_payload.get("trace_id")) or None,
        "session_id": _string(session_id) or _string(source_payload.get("session_id")) or None,
        "incident_id": _string(incident_id) or _string(source_payload.get("incident_id")) or None,
        "review_id": _string(review_id) or _string(source_payload.get("review_id")) or None,
        "scan_id": _string(scan_id) or _string(source_payload.get("scan_id")) or None,
        "result": resolved_result,
        "outcome": resolved_result,
        "source": resolved_source,
        "message": _string(message) or _string(source_payload.get("message")) or resolved_action,
        "ip_address": _string(ip_address) or _string(source_payload.get("ip_address")) or None,
        "user_agent": _string(user_agent) or _string(source_payload.get("user_agent")) or None,
        "metadata": metadata if isinstance(metadata, dict) else _mapping(source_payload.get("metadata")),
        "changes": changes if isinstance(changes, dict) else _mapping(source_payload.get("changes")),
        "tags": _listify(tags if tags is not None else source_payload.get("tags")),
        "created_at": resolved_created_at,
        "occurred_at": resolved_occurred_at,
    }


@dataclass(slots=True)  # slots reduce per-instance overhead for simple containers [web:121][web:124]
class AuditLogService:
    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_AUDIT_LOG_TABLE

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
        health = getattr(self.backend, "healthcheck", None)
        if callable(health):
            return bool(health())
        return True

    def write_log(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        record = _normalize_audit_log_payload(payload, **kwargs)
        inserted = self.backend.insert(self.table_name, record)
        if isinstance(inserted, list) and inserted:
            return dict(inserted[0])
        if isinstance(inserted, dict):
            return dict(inserted)
        return record

    def log(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.write_log(payload, **kwargs)

    def record(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.write_log(payload, **kwargs)

    def list_logs(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        organization_id: str | None = None,
        actor_id: str | None = None,
        action: str | None = None,
        category: str | None = None,
        result: str | None = None,
        request_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query_filters: dict[str, Any] = dict(filters or {})
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if actor_id:
            query_filters.setdefault("actor_id", actor_id)
        if action:
            query_filters.setdefault("action", action)
        if category:
            query_filters.setdefault("category", category)
        if result:
            query_filters.setdefault("result", _normalize_result(result))
        if request_id:
            query_filters.setdefault("request_id", request_id)

        rows = self.backend.select(
            self.table_name,
            limit=limit,
            filters=query_filters or None,
        )
        items = [dict(row) for row in rows]
        items.sort(
            key=lambda row: _normalize_timestamp(row.get("occurred_at") or row.get("created_at")),
            reverse=True,
        )
        return items

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_logs(**kwargs)

    def get_log(self, log_id: str) -> dict[str, Any] | None:
        normalized_id = _string(log_id)
        if not normalized_id:
            raise ValueError("log_id is required")

        for key in ("log_id", "audit_id", "id"):
            rows = self.backend.select(self.table_name, filters={key: normalized_id}, limit=1)
            if rows:
                return dict(rows[0])
        return None

    def get(self, log_id: str) -> dict[str, Any] | None:
        return self.get_log(log_id)

    def delete_log(self, log_id: str) -> dict[str, Any] | None:
        normalized_id = _string(log_id)
        if not normalized_id:
            raise ValueError("log_id is required")

        for key in ("log_id", "audit_id", "id"):
            deleted = self.backend.delete(self.table_name, filters={key: normalized_id})
            if isinstance(deleted, list) and deleted:
                return dict(deleted[0])
        return None

    def summarize(
        self,
        *,
        organization_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        logs = self.list_logs(limit=limit, organization_id=organization_id)
        by_action: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_result: dict[str, int] = {}

        for item in logs:
            action = _string(item.get("action"), _AUDIT_ACTION_FALLBACK)
            category = _string(item.get("category"), "unknown")
            result = _string(item.get("result"), "unknown")
            by_action[action] = by_action.get(action, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1
            by_result[result] = by_result.get(result, 0) + 1

        return {
            "total_logs": len(logs),
            "by_action": by_action,
            "by_category": by_category,
            "by_result": by_result,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


def build_audit_log_service(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_AUDIT_LOG_TABLE,
    **store_kwargs: Any,
) -> AuditLogService:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return AuditLogService(backend=resolved_backend, table_name=table_name)


def create_audit_log_service(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_AUDIT_LOG_TABLE,
    **store_kwargs: Any,
) -> AuditLogService:
    return build_audit_log_service(backend=backend, table_name=table_name, **store_kwargs)


def get_audit_log_service(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_AUDIT_LOG_TABLE,
    **store_kwargs: Any,
) -> AuditLogService:
    return build_audit_log_service(backend=backend, table_name=table_name, **store_kwargs)