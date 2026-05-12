from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.persistencebootstrap import build_store

DEFAULT_REPORT_TABLE = "reports"

_REPORT_TYPES = {
    "executive_summary",
    "incident_report",
    "security_assessment",
    "operations_summary",
    "telemetry_summary",
    "audit_summary",
    "custom",
}

_REPORT_STATUSES = {
    "draft",
    "ready",
    "published",
    "archived",
}

_DEFAULT_REPORT_TYPE = "custom"
_DEFAULT_REPORT_STATUS = "draft"


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
    if isinstance(value, Mapping):  # Mapping accepts broader mapping-like inputs [web:115]
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
            key: item
            for key, item in vars(value).items()
            if not key.startswith("_") and not callable(item)
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


def _normalize_report_type(value: Any) -> str:
    normalized = _string(value, _DEFAULT_REPORT_TYPE).lower()
    if normalized in {"incident", "incident_summary"}:
        normalized = "incident_report"
    if normalized in {"executive", "executive_report"}:
        normalized = "executive_summary"
    if normalized not in _REPORT_TYPES:
        return _DEFAULT_REPORT_TYPE
    return normalized


def _normalize_report_status(value: Any) -> str:
    normalized = _string(value, _DEFAULT_REPORT_STATUS).lower()
    if normalized in {"complete", "completed"}:
        normalized = "ready"
    if normalized not in _REPORT_STATUSES:
        return _DEFAULT_REPORT_STATUS
    return normalized


def _normalize_report_payload(
    payload: dict[str, Any] | None = None,
    *,
    report_id: str | None = None,
    title: str | None = None,
    summary: str | None = None,
    description: str | None = None,
    report_type: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    owner_id: str | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    customer_id: str | None = None,
    author_id: str | None = None,
    generated_by: str | None = None,
    source: str | None = None,
    incident_id: str | None = None,
    review_id: str | None = None,
    scan_id: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    session_id: str | None = None,
    content: dict[str, Any] | None = None,
    findings: list[Any] | None = None,
    recommendations: list[Any] | None = None,
    attachments: list[Any] | None = None,
    tags: list[Any] | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: str | datetime | None = None,
    updated_at: str | datetime | None = None,
    generated_at: str | datetime | None = None,
    published_at: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _mapping(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    resolved_report_id = (
        _string(report_id)
        or _string(source_payload.get("report_id"))
        or _string(source_payload.get("id"))
        or str(uuid4())
    )

    resolved_report_type = _normalize_report_type(
        report_type or source_payload.get("report_type")
    )

    resolved_status = _normalize_report_status(
        status or source_payload.get("status")
    )

    resolved_org = (
        _string(organization_id)
        or _string(org_id)
        or _string(customer_id)
        or _string(source_payload.get("organization_id"))
        or _string(source_payload.get("org_id"))
        or _string(source_payload.get("customer_id"))
    )

    resolved_title = (
        _string(title)
        or _string(source_payload.get("title"))
        or _string(summary)
        or _string(source_payload.get("summary"))
        or f"{resolved_report_type.replace('_', ' ').title()} Report"
    )

    resolved_summary = (
        _string(summary)
        or _string(source_payload.get("summary"))
        or _string(description)
        or _string(source_payload.get("description"))
        or resolved_title
    )

    resolved_description = (
        _string(description)
        or _string(source_payload.get("description"))
        or resolved_summary
    )

    resolved_source = (
        _string(source)
        or _string(source_payload.get("source"))
        or "ironclaw"
    )

    resolved_created_at = _normalize_timestamp(
        created_at or source_payload.get("created_at") or generated_at or source_payload.get("generated_at")
    )
    resolved_updated_at = _normalize_timestamp(
        updated_at or source_payload.get("updated_at") or resolved_created_at
    )
    resolved_generated_at = _normalize_timestamp(
        generated_at or source_payload.get("generated_at") or resolved_created_at
    )
    resolved_published_at = (
        _normalize_timestamp(published_at or source_payload.get("published_at"))
        if (published_at is not None or source_payload.get("published_at") is not None)
        else None
    )

    if resolved_status == "published" and resolved_published_at is None:
        resolved_published_at = resolved_updated_at

    return {
        "report_id": resolved_report_id,
        "id": resolved_report_id,
        "title": resolved_title,
        "summary": resolved_summary,
        "description": resolved_description,
        "report_type": resolved_report_type,
        "status": resolved_status,
        "severity": _string(severity) or _string(source_payload.get("severity")) or None,
        "owner_id": _string(owner_id) or _string(source_payload.get("owner_id")) or None,
        "organization_id": resolved_org or None,
        "org_id": resolved_org or None,
        "customer_id": resolved_org or None,
        "author_id": _string(author_id) or _string(source_payload.get("author_id")) or None,
        "generated_by": _string(generated_by) or _string(source_payload.get("generated_by")) or None,
        "source": resolved_source,
        "incident_id": _string(incident_id) or _string(source_payload.get("incident_id")) or None,
        "review_id": _string(review_id) or _string(source_payload.get("review_id")) or None,
        "scan_id": _string(scan_id) or _string(source_payload.get("scan_id")) or None,
        "request_id": _string(request_id) or _string(source_payload.get("request_id")) or None,
        "trace_id": _string(trace_id) or _string(source_payload.get("trace_id")) or None,
        "session_id": _string(session_id) or _string(source_payload.get("session_id")) or None,
        "content": content if isinstance(content, dict) else _mapping(source_payload.get("content")),
        "findings": _listify(findings if findings is not None else source_payload.get("findings")),
        "recommendations": _listify(
            recommendations if recommendations is not None else source_payload.get("recommendations")
        ),
        "attachments": _listify(attachments if attachments is not None else source_payload.get("attachments")),
        "tags": _listify(tags if tags is not None else source_payload.get("tags")),
        "metadata": metadata if isinstance(metadata, dict) else _mapping(source_payload.get("metadata")),
        "created_at": resolved_created_at,
        "updated_at": resolved_updated_at,
        "generated_at": resolved_generated_at,
        "published_at": resolved_published_at,
    }


@dataclass(slots=True)  # slots help data-container style services stay lean [web:121][web:124]
class ReportService:
    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_REPORT_TABLE

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

    def create_report(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        record = _normalize_report_payload(payload, **kwargs)
        inserted = self.backend.insert(self.table_name, record)
        if isinstance(inserted, list) and inserted:
            return dict(inserted[0])
        if isinstance(inserted, dict):
            return dict(inserted)
        return record

    def create(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.create_report(payload, **kwargs)

    def generate_report(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.create_report(payload, **kwargs)

    def list_reports(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        organization_id: str | None = None,
        owner_id: str | None = None,
        report_type: str | None = None,
        status: str | None = None,
        incident_id: str | None = None,
        scan_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query_filters: dict[str, Any] = dict(filters or {})
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if owner_id:
            query_filters.setdefault("owner_id", owner_id)
        if report_type:
            query_filters.setdefault("report_type", _normalize_report_type(report_type))
        if status:
            query_filters.setdefault("status", _normalize_report_status(status))
        if incident_id:
            query_filters.setdefault("incident_id", incident_id)
        if scan_id:
            query_filters.setdefault("scan_id", scan_id)

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
        return self.list_reports(**kwargs)

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        normalized_id = _string(report_id)
        if not normalized_id:
            raise ValueError("report_id is required")

        rows = self.backend.select(self.table_name, filters={"report_id": normalized_id}, limit=1)
        if rows:
            return dict(rows[0])

        rows = self.backend.select(self.table_name, filters={"id": normalized_id}, limit=1)
        if rows:
            return dict(rows[0])

        return None

    def get(self, report_id: str) -> dict[str, Any] | None:
        return self.get_report(report_id)

    def update_report(self, report_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_report(report_id)
        if existing is None:
            return None

        merged = dict(existing)
        merged.update(_mapping(updates))
        merged["report_id"] = existing.get("report_id") or existing.get("id") or report_id
        merged["id"] = merged["report_id"]
        merged["updated_at"] = _utc_now()

        normalized = _normalize_report_payload(merged)

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"report_id": report_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"id": report_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        return normalized

    def update(self, report_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        return self.update_report(report_id, updates)

    def publish_report(self, report_id: str) -> dict[str, Any] | None:
        return self.update_report(
            report_id,
            {
                "status": "published",
                "published_at": _utc_now(),
            },
        )

    def archive_report(self, report_id: str) -> dict[str, Any] | None:
        return self.update_report(report_id, {"status": "archived"})

    def delete_report(self, report_id: str) -> dict[str, Any] | None:
        normalized_id = _string(report_id)
        if not normalized_id:
            raise ValueError("report_id is required")

        deleted = self.backend.delete(self.table_name, filters={"report_id": normalized_id})
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
        reports = self.list_reports(limit=limit, organization_id=organization_id)
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}

        for report in reports:
            report_type = _string(report.get("report_type"), "unknown")
            status = _string(report.get("status"), "unknown")
            by_type[report_type] = by_type.get(report_type, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1

        return {
            "total_reports": len(reports),
            "by_type": by_type,
            "by_status": by_status,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


def build_report_service(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_REPORT_TABLE,
    **store_kwargs: Any,
) -> ReportService:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return ReportService(backend=resolved_backend, table_name=table_name)


def create_report_service(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_REPORT_TABLE,
    **store_kwargs: Any,
) -> ReportService:
    return build_report_service(backend=backend, table_name=table_name, **store_kwargs)


def get_report_service(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_REPORT_TABLE,
    **store_kwargs: Any,
) -> ReportService:
    return build_report_service(backend=backend, table_name=table_name, **store_kwargs)