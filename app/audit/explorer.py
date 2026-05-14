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
    if isinstance(value, int | float):
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
class AuditExplorerFacet:
    key: str
    label: str
    count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "count": self.count,
        }


@dataclass(frozen=True, slots=True)
class AuditExplorerRecord:
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    result: str
    actor: str
    resource: str
    summary: str
    request_id: str = ""
    trace_id: str = ""
    org_id: str = ""
    review_state: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": _isoformat(self.timestamp),
            "event_type": self.event_type,
            "severity": self.severity,
            "result": self.result,
            "actor": self.actor,
            "resource": self.resource,
            "summary": self.summary,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "org_id": self.org_id,
            "review_state": self.review_state,
        }


@dataclass(frozen=True, slots=True)
class AuditExplorer:
    query: str = ""
    total_results: int = 0
    returned_results: int = 0
    page: int = 1
    page_size: int = 25
    has_more: bool = False
    severity_facets: tuple[AuditExplorerFacet, ...] = ()
    result_facets: tuple[AuditExplorerFacet, ...] = ()
    event_type_facets: tuple[AuditExplorerFacet, ...] = ()
    records: tuple[AuditExplorerRecord, ...] = ()
    generated_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "total_results": self.total_results,
            "returned_results": self.returned_results,
            "page": self.page,
            "page_size": self.page_size,
            "has_more": self.has_more,
            "severity_facets": [item.to_dict() for item in self.severity_facets],
            "result_facets": [item.to_dict() for item in self.result_facets],
            "event_type_facets": [item.to_dict() for item in self.event_type_facets],
            "records": [item.to_dict() for item in self.records],
            "generated_at": _isoformat(self.generated_at),
        }


def _normalize_facet(value: Any) -> AuditExplorerFacet | None:
    if not isinstance(value, dict):
        return None

    key = _coerce_str(value.get("key"))
    label = _coerce_str(value.get("label"), key)
    if not key and not label:
        return None

    return AuditExplorerFacet(
        key=key or label.lower().replace(" ", "_"),
        label=label or key,
        count=max(0, _coerce_int(value.get("count"), 0)),
    )


def _normalize_record(value: Any) -> AuditExplorerRecord | None:
    if not isinstance(value, dict):
        return None

    event_id = _coerce_str(value.get("event_id"))
    event_type = _coerce_str(value.get("event_type"))
    summary = _coerce_str(value.get("summary") or value.get("message"))
    if not any([event_id, event_type, summary]):
        return None

    actor_value = value.get("actor")
    if isinstance(actor_value, dict):
        actor = _coerce_str(
            actor_value.get("display_name") or actor_value.get("actor_id") or actor_value.get("actor_type"),
            "System",
        )
    else:
        actor = _coerce_str(actor_value, "System") or "System"

    return AuditExplorerRecord(
        event_id=event_id or "audit-event",
        timestamp=_coerce_datetime(value.get("timestamp") or value.get("created_at"), _utc_now()) or _utc_now(),
        event_type=event_type or "audit.event",
        severity=_coerce_str(value.get("severity"), "info") or "info",
        result=_coerce_str(value.get("result"), "success") or "success",
        actor=actor,
        resource=_coerce_str(value.get("resource"), "system") or "system",
        summary=summary or "Audit explorer event recorded.",
        request_id=_coerce_str(value.get("request_id")),
        trace_id=_coerce_str(value.get("trace_id")),
        org_id=_coerce_str(value.get("org_id")),
        review_state=_coerce_str(value.get("review_state"), "none") or "none",
    )


def _normalize_facet_list(values: Any) -> tuple[AuditExplorerFacet, ...]:
    if not isinstance(values, list):
        return ()
    return tuple(item for value in values if (item := _normalize_facet(value)) is not None)


def _normalize_record_list(values: Any) -> tuple[AuditExplorerRecord, ...]:
    if not isinstance(values, list):
        return ()
    return tuple(item for value in values if (item := _normalize_record(value)) is not None)


def default_audit_explorer() -> AuditExplorer:
    return AuditExplorer()


def build_audit_explorer(
    data: dict[str, Any] | None = None,
    *,
    baseline: AuditExplorer | None = None,
) -> AuditExplorer:
    source = data or {}
    current = baseline or default_audit_explorer()

    records = _normalize_record_list(source.get("records")) or current.records
    page = max(1, _coerce_int(source.get("page"), current.page))
    page_size = max(1, _coerce_int(source.get("page_size"), current.page_size))
    returned_results = _coerce_int(source.get("returned_results"), len(records))
    total_results = _coerce_int(source.get("total_results"), returned_results)

    total_results = max(total_results, returned_results)

    return AuditExplorer(
        query=_coerce_str(source.get("query"), current.query),
        total_results=total_results,
        returned_results=max(0, returned_results),
        page=page,
        page_size=page_size,
        has_more=_coerce_bool(source.get("has_more"), total_results > page * page_size),
        severity_facets=_normalize_facet_list(source.get("severity_facets")) or current.severity_facets,
        result_facets=_normalize_facet_list(source.get("result_facets")) or current.result_facets,
        event_type_facets=_normalize_facet_list(source.get("event_type_facets")) or current.event_type_facets,
        records=records,
        generated_at=_coerce_datetime(source.get("generated_at"), _utc_now()) or _utc_now(),
    )


def audit_explorer_summary(explorer: AuditExplorer) -> dict[str, Any]:
    critical_results = sum(1 for record in explorer.records if record.severity.lower() == "critical")
    review_queue_results = sum(1 for record in explorer.records if record.review_state.lower() not in {"", "none", "closed", "resolved"})

    return {
        "query": explorer.query,
        "pagination": {
            "page": explorer.page,
            "page_size": explorer.page_size,
            "returned_results": explorer.returned_results,
            "total_results": explorer.total_results,
            "has_more": explorer.has_more,
        },
        "facets": {
            "severity": [item.to_dict() for item in explorer.severity_facets],
            "result": [item.to_dict() for item in explorer.result_facets],
            "event_type": [item.to_dict() for item in explorer.event_type_facets],
        },
        "records": [item.to_dict() for item in explorer.records],
        "signals": {
            "critical_results": critical_results,
            "review_queue_results": review_queue_results,
        },
        "generated_at": _isoformat(explorer.generated_at),
    }
