from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.persistencebootstrap import build_store

DEFAULT_ALERT_TABLE = "alerts"

_ALERT_STATUSES = {
    "open",
    "new",
    "acknowledged",
    "investigating",
    "suppressed",
    "resolved",
    "closed",
    "false_positive",
}

_ALERT_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}

_ALERT_VERDICTS = {
    "pending",
    "suspicious",
    "benign",
    "malicious",
    "false_positive",
}

_DEFAULT_STATUS = "open"
_DEFAULT_SEVERITY = "medium"
_DEFAULT_VERDICT = "pending"


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
        return {key: val for key, val in vars(value).items() if not key.startswith("_") and not callable(val)}
    raise TypeError("value is not serializable to dict")


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _normalize_status(value: Any) -> str:
    normalized = _string(value, _DEFAULT_STATUS).lower()
    if normalized in {"active", "triggered"}:
        normalized = "open"
    if normalized in {"in_progress", "triaging"}:
        normalized = "investigating"
    if normalized not in _ALERT_STATUSES:
        return _DEFAULT_STATUS
    return normalized


def _normalize_severity(value: Any) -> str:
    normalized = _string(value, _DEFAULT_SEVERITY).lower()
    if normalized not in _ALERT_SEVERITIES:
        return _DEFAULT_SEVERITY
    return normalized


def _normalize_verdict(value: Any) -> str:
    normalized = _string(value, _DEFAULT_VERDICT).lower()
    if normalized in {"unknown", "unreviewed"}:
        normalized = "pending"
    if normalized not in _ALERT_VERDICTS:
        return _DEFAULT_VERDICT
    return normalized


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "y", "on", "enabled"}:
        return True
    if lowered in {"0", "false", "no", "n", "off", "disabled"}:
        return False
    return default


def _normalize_alert_payload(
    payload: dict[str, Any] | None = None,
    *,
    alert_id: str | None = None,
    title: str | None = None,
    summary: str | None = None,
    description: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    verdict: str | None = None,
    category: str | None = None,
    alert_type: str | None = None,
    source: str | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    customer_id: str | None = None,
    owner_id: str | None = None,
    assigned_to: str | None = None,
    incident_id: str | None = None,
    review_id: str | None = None,
    scan_id: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    session_id: str | None = None,
    dedupe_key: str | None = None,
    actor: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    evidence: list[Any] | None = None,
    tags: list[Any] | None = None,
    suppressed: Any = None,
    created_at: str | datetime | None = None,
    updated_at: str | datetime | None = None,
    detected_at: str | datetime | None = None,
    acknowledged_at: str | datetime | None = None,
    resolved_at: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _mapping(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    resolved_alert_id = _string(alert_id) or _string(source_payload.get("alert_id")) or _string(source_payload.get("id")) or str(uuid4())

    resolved_title = _string(title) or _string(source_payload.get("title")) or _string(summary) or _string(source_payload.get("summary")) or _string(description) or _string(source_payload.get("description")) or "Security alert"

    resolved_summary = _string(summary) or _string(source_payload.get("summary")) or _string(description) or _string(source_payload.get("description")) or resolved_title

    resolved_description = _string(description) or _string(source_payload.get("description")) or resolved_summary

    resolved_status = _normalize_status(status or source_payload.get("status"))
    resolved_severity = _normalize_severity(severity or source_payload.get("severity"))
    resolved_verdict = _normalize_verdict(verdict or source_payload.get("verdict"))

    resolved_category = _string(category) or _string(alert_type) or _string(source_payload.get("category")) or _string(source_payload.get("alert_type")) or "security"

    resolved_source = _string(source) or _string(source_payload.get("source")) or "ironclaw"

    resolved_org = _string(organization_id) or _string(org_id) or _string(customer_id) or _string(source_payload.get("organization_id")) or _string(source_payload.get("org_id")) or _string(source_payload.get("customer_id"))

    resolved_created_at = _normalize_timestamp(
        created_at or source_payload.get("created_at") or detected_at or source_payload.get("detected_at"),
    )
    resolved_updated_at = _normalize_timestamp(
        updated_at or source_payload.get("updated_at") or resolved_created_at,
    )
    resolved_detected_at = _normalize_timestamp(
        detected_at or source_payload.get("detected_at") or resolved_created_at,
    )

    resolved_acknowledged_at = _normalize_timestamp(acknowledged_at or source_payload.get("acknowledged_at")) if (acknowledged_at is not None or source_payload.get("acknowledged_at") is not None) else None

    resolved_resolved_at = _normalize_timestamp(resolved_at or source_payload.get("resolved_at")) if (resolved_at is not None or source_payload.get("resolved_at") is not None) else None

    if resolved_status == "acknowledged" and resolved_acknowledged_at is None:
        resolved_acknowledged_at = resolved_updated_at

    if resolved_status in {"resolved", "closed", "false_positive"} and resolved_resolved_at is None:
        resolved_resolved_at = resolved_updated_at

    resolved_actor = actor if isinstance(actor, dict) else _mapping(source_payload.get("actor"))
    resolved_target = target if isinstance(target, dict) else _mapping(source_payload.get("target"))
    resolved_metadata = metadata if isinstance(metadata, dict) else _mapping(source_payload.get("metadata"))

    resolved_suppressed = _bool(
        suppressed if suppressed is not None else source_payload.get("suppressed"),
        default=resolved_status == "suppressed",
    )

    dedupe = _string(dedupe_key) or _string(source_payload.get("dedupe_key")) or _string(source_payload.get("fingerprint")) or None

    return {
        "alert_id": resolved_alert_id,
        "id": resolved_alert_id,
        "title": resolved_title,
        "summary": resolved_summary,
        "description": resolved_description,
        "status": resolved_status,
        "severity": resolved_severity,
        "verdict": resolved_verdict,
        "category": resolved_category,
        "alert_type": resolved_category,
        "source": resolved_source,
        "organization_id": resolved_org or None,
        "org_id": resolved_org or None,
        "customer_id": resolved_org or None,
        "owner_id": _string(owner_id) or _string(source_payload.get("owner_id")) or None,
        "assigned_to": _string(assigned_to) or _string(source_payload.get("assigned_to")) or None,
        "incident_id": _string(incident_id) or _string(source_payload.get("incident_id")) or None,
        "review_id": _string(review_id) or _string(source_payload.get("review_id")) or None,
        "scan_id": _string(scan_id) or _string(source_payload.get("scan_id")) or None,
        "request_id": _string(request_id) or _string(source_payload.get("request_id")) or None,
        "trace_id": _string(trace_id) or _string(source_payload.get("trace_id")) or None,
        "session_id": _string(session_id) or _string(source_payload.get("session_id")) or None,
        "dedupe_key": dedupe,
        "actor": resolved_actor,
        "target": resolved_target,
        "metadata": resolved_metadata,
        "evidence": _listify(evidence if evidence is not None else source_payload.get("evidence")),
        "tags": _listify(tags if tags is not None else source_payload.get("tags")),
        "suppressed": resolved_suppressed,
        "created_at": resolved_created_at,
        "updated_at": resolved_updated_at,
        "detected_at": resolved_detected_at,
        "acknowledged_at": resolved_acknowledged_at,
        "resolved_at": resolved_resolved_at,
    }


@dataclass(slots=True)
class SecurityAlertStore:
    """Persistence-backed store for security alert records (incidents, threats,
    policy violations). Full alert lifecycle: open → acknowledge → investigate
    → resolve / close / false_positive.

    Distinct from AlertEndpointStore in alert_store.py, which manages
    notification routing targets (email / webhook / slack endpoints).
    """

    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_ALERT_TABLE

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

    def create_alert(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        record = _normalize_alert_payload(payload, **kwargs)
        inserted = self.backend.insert(self.table_name, record)
        if isinstance(inserted, list) and inserted:
            return dict(inserted[0])
        if isinstance(inserted, dict):
            return dict(inserted)
        return record

    def create(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.create_alert(payload, **kwargs)

    def open_alert(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.create_alert(payload, **kwargs)

    def list_alerts(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        organization_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: str | None = None,
        category: str | None = None,
        incident_id: str | None = None,
        scan_id: str | None = None,
        source: str | None = None,
    ) -> list[dict[str, Any]]:
        query_filters: dict[str, Any] = dict(filters or {})
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if status:
            query_filters.setdefault("status", _normalize_status(status))
        if severity:
            query_filters.setdefault("severity", _normalize_severity(severity))
        if assigned_to:
            query_filters.setdefault("assigned_to", assigned_to)
        if category:
            query_filters.setdefault("category", category)
        if incident_id:
            query_filters.setdefault("incident_id", incident_id)
        if scan_id:
            query_filters.setdefault("scan_id", scan_id)
        if source:
            query_filters.setdefault("source", source)

        rows = self.backend.select(
            self.table_name,
            limit=limit,
            filters=query_filters or None,
        )
        items = [dict(row) for row in rows]
        items.sort(
            key=lambda row: _normalize_timestamp(row.get("updated_at") or row.get("created_at")),
            reverse=True,
        )
        return items

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_alerts(**kwargs)

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        normalized_id = _string(alert_id)
        if not normalized_id:
            raise ValueError("alert_id is required")

        rows = self.backend.select(self.table_name, filters={"alert_id": normalized_id}, limit=1)
        if rows:
            return dict(rows[0])

        rows = self.backend.select(self.table_name, filters={"id": normalized_id}, limit=1)
        if rows:
            return dict(rows[0])

        return None

    def get(self, alert_id: str) -> dict[str, Any] | None:
        return self.get_alert(alert_id)

    def update_alert(self, alert_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_alert(alert_id)
        if existing is None:
            return None

        merged = dict(existing)
        merged.update(_mapping(updates))
        merged["alert_id"] = existing.get("alert_id") or existing.get("id") or alert_id
        merged["id"] = merged["alert_id"]
        merged["updated_at"] = _utc_now()

        if _normalize_status(merged.get("status")) == "acknowledged" and not merged.get("acknowledged_at"):
            merged["acknowledged_at"] = merged["updated_at"]

        if _normalize_status(merged.get("status")) in {
            "resolved",
            "closed",
            "false_positive",
        } and not merged.get("resolved_at"):
            merged["resolved_at"] = merged["updated_at"]

        normalized = _normalize_alert_payload(merged)

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"alert_id": alert_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"id": alert_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        return normalized

    def update(self, alert_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        return self.update_alert(alert_id, updates)

    def acknowledge_alert(
        self,
        alert_id: str,
        *,
        assigned_to: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "acknowledged",
            "acknowledged_at": _utc_now(),
        }
        if assigned_to is not None:
            updates["assigned_to"] = assigned_to
        if metadata:
            current = self.get_alert(alert_id) or {}
            merged_metadata = _mapping(current.get("metadata"))
            merged_metadata.update(metadata)
            updates["metadata"] = merged_metadata
        return self.update_alert(alert_id, updates)

    def assign_alert(self, alert_id: str, assigned_to: str) -> dict[str, Any] | None:
        return self.update_alert(
            alert_id,
            {
                "assigned_to": assigned_to,
                "status": "investigating",
            },
        )

    def suppress_alert(
        self,
        alert_id: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "suppressed",
            "suppressed": True,
        }
        if metadata:
            current = self.get_alert(alert_id) or {}
            merged_metadata = _mapping(current.get("metadata"))
            merged_metadata.update(metadata)
            updates["metadata"] = merged_metadata
        return self.update_alert(alert_id, updates)

    def resolve_alert(
        self,
        alert_id: str,
        *,
        verdict: str | None = None,
        incident_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "resolved",
            "resolved_at": _utc_now(),
        }
        if verdict is not None:
            updates["verdict"] = verdict
        if incident_id is not None:
            updates["incident_id"] = incident_id
        if metadata:
            current = self.get_alert(alert_id) or {}
            merged_metadata = _mapping(current.get("metadata"))
            merged_metadata.update(metadata)
            updates["metadata"] = merged_metadata
        return self.update_alert(alert_id, updates)

    def close_alert(
        self,
        alert_id: str,
        *,
        verdict: str | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "closed",
            "resolved_at": _utc_now(),
        }
        if verdict is not None:
            updates["verdict"] = verdict
        return self.update_alert(alert_id, updates)

    def mark_false_positive(
        self,
        alert_id: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "false_positive",
            "verdict": "false_positive",
            "resolved_at": _utc_now(),
        }
        if metadata:
            current = self.get_alert(alert_id) or {}
            merged_metadata = _mapping(current.get("metadata"))
            merged_metadata.update(metadata)
            updates["metadata"] = merged_metadata
        return self.update_alert(alert_id, updates)

    def delete_alert(self, alert_id: str) -> dict[str, Any] | None:
        normalized_id = _string(alert_id)
        if not normalized_id:
            raise ValueError("alert_id is required")

        deleted = self.backend.delete(self.table_name, filters={"alert_id": normalized_id})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        deleted = self.backend.delete(self.table_name, filters={"id": normalized_id})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        return None

    def summarize(
        self,
        *,
        organization_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        alerts = self.list_alerts(limit=limit, organization_id=organization_id)

        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_verdict: dict[str, int] = {}

        for item in alerts:
            status = _string(item.get("status"), "unknown")
            severity = _string(item.get("severity"), "unknown")
            category = _string(item.get("category"), "unknown")
            verdict = _string(item.get("verdict"), "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1
            by_verdict[verdict] = by_verdict.get(verdict, 0) + 1

        return {
            "total_alerts": len(alerts),
            "open": by_status.get("open", 0),
            "acknowledged": by_status.get("acknowledged", 0),
            "investigating": by_status.get("investigating", 0),
            "resolved": by_status.get("resolved", 0),
            "closed": by_status.get("closed", 0),
            "false_positive": by_status.get("false_positive", 0),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_category": by_category,
            "by_verdict": by_verdict,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


def build_alert_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_ALERT_TABLE,
    **store_kwargs: Any,
) -> SecurityAlertStore:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return SecurityAlertStore(backend=resolved_backend, table_name=table_name)


def create_alert_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_ALERT_TABLE,
    **store_kwargs: Any,
) -> SecurityAlertStore:
    return build_alert_store(backend=backend, table_name=table_name, **store_kwargs)


def get_alert_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_ALERT_TABLE,
    **store_kwargs: Any,
) -> SecurityAlertStore:
    return build_alert_store(backend=backend, table_name=table_name, **store_kwargs)
