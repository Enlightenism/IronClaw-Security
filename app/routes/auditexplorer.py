from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.ui.audit.explorer import get_audit_explorer_data

router = APIRouter(prefix="/ui/audit", tags=["audit-explorer"])


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_lower(value: Any) -> str | None:
    text = _normalize_text(value)
    return text.lower() if text else None


def _safe_metadata(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _match_text(value: Any, expected: str | None) -> bool:
    if not expected:
        return True
    candidate = _normalize_lower(value)
    return candidate is not None and expected in candidate


def _coerce_limit(limit: int) -> int:
    return max(1, min(limit, 500))


class AuditExplorerFilterOptions(BaseModel):
    severities: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    verdicts: list[str] = Field(default_factory=list)
    actor_ids: list[str] = Field(default_factory=list)
    integration_ids: list[str] = Field(default_factory=list)


class AuditExplorerCounts(BaseModel):
    total_events: int = 0
    critical_events: int = 0
    high_severity_events: int = 0
    blocked_events: int = 0
    quarantined_events: int = 0
    unique_actors: int = 0
    unique_sessions: int = 0
    unique_traces: int = 0
    unique_integrations: int = 0


class AuditExplorerSummary(BaseModel):
    title: str
    subtitle: str
    generated_at: str
    active_filters: dict[str, str] = Field(default_factory=dict)
    counts: AuditExplorerCounts
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    verdict_breakdown: dict[str, int] = Field(default_factory=dict)
    event_type_breakdown: dict[str, int] = Field(default_factory=dict)
    top_actors: list[str] = Field(default_factory=list)
    top_integrations: list[str] = Field(default_factory=list)


class AuditExplorerRow(BaseModel):
    event_id: str
    created_at: str
    event_type: str
    severity: str
    summary: str
    actor_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    integration_id: str | None = None
    verdict: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    badges: list[str] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)
    detail_path: str


class AuditExplorerResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    summary: AuditExplorerSummary
    filters: AuditExplorerFilterOptions
    items: list[AuditExplorerRow] = Field(default_factory=list)
    total: int = 0
    limit: int
    has_more: bool = False
    empty_state: str | None = None
    notes: list[str] = Field(default_factory=list)


def _extract_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _collect_filter_options(items: list[dict[str, Any]]) -> AuditExplorerFilterOptions:
    severities = sorted(
        {value for item in items if (value := _normalize_lower(item.get("severity")))},
    )
    event_types = sorted(
        {value for item in items if (value := _normalize_lower(item.get("event_type")))},
    )
    verdicts = sorted(
        {value for item in items if (value := _normalize_lower(item.get("verdict")))},
    )
    actor_ids = sorted(
        {value for item in items if (value := _normalize_text(item.get("actor_id")))},
    )
    integration_ids = sorted(
        {value for item in items if (value := _normalize_text(item.get("integration_id")))},
    )
    return AuditExplorerFilterOptions(
        severities=severities,
        event_types=event_types,
        verdicts=verdicts,
        actor_ids=actor_ids,
        integration_ids=integration_ids,
    )


def _apply_filters(
    items: list[dict[str, Any]],
    *,
    actor_id: str | None,
    request_id: str | None,
    trace_id: str | None,
    event_type: str | None,
    severity: str | None,
    verdict: str | None,
    integration_id: str | None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for item in items:
        if not _match_text(item.get("actor_id"), actor_id):
            continue
        if not _match_text(item.get("request_id"), request_id):
            continue
        if not _match_text(item.get("trace_id"), trace_id):
            continue
        if not _match_text(item.get("event_type"), event_type):
            continue
        if not _match_text(item.get("severity"), severity):
            continue
        if not _match_text(item.get("verdict"), verdict):
            continue
        if not _match_text(item.get("integration_id"), integration_id):
            continue
        filtered.append(item)
    return filtered


def _severity_rank(value: Any) -> int:
    normalized = _normalize_lower(value)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(normalized or "", 4)


def _build_badges(item: dict[str, Any]) -> list[str]:
    badges: list[str] = []
    severity = _normalize_lower(item.get("severity"))
    verdict = _normalize_lower(item.get("verdict"))
    event_type = _normalize_text(item.get("event_type"))

    if severity:
        badges.append(severity)
    if verdict and verdict not in badges:
        badges.append(verdict)
    if event_type:
        badges.append(event_type)

    return badges[:4]


def _build_risk_flags(item: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    severity = _normalize_lower(item.get("severity"))
    verdict = _normalize_lower(item.get("verdict"))
    metadata = _safe_metadata(item.get("metadata"))

    if severity == "critical":
        flags.append("critical")
    elif severity == "high":
        flags.append("high-risk")

    # Keep legacy verdict flags available for historical audit rows.
    if verdict in {"block", "blocked"}:
        flags.append("blocked")
    elif verdict == "quarantine":
        flags.append("quarantined")
    elif verdict == "warn":
        flags.append("warned")

    if metadata.get("requires_review") is True:
        flags.append("review")
    if metadata.get("policy_hit_count", 0):
        flags.append("policy-hit")
    if metadata.get("telemetry_gap") is True:
        flags.append("telemetry-gap")

    deduped: list[str] = []
    for flag in flags:
        if flag not in deduped:
            deduped.append(flag)
    return deduped[:5]


def _build_row(item: dict[str, Any]) -> AuditExplorerRow:
    event_id = _normalize_text(item.get("event_id")) or "unknown-event"
    request_id = _normalize_text(item.get("request_id"))
    trace_id = _normalize_text(item.get("trace_id"))
    actor_id = _normalize_text(item.get("actor_id"))
    session_id = _normalize_text(item.get("session_id"))
    integration_id = _normalize_text(item.get("integration_id"))
    event_type = _normalize_text(item.get("event_type")) or "unknown"
    severity = _normalize_lower(item.get("severity")) or "unknown"
    summary = _normalize_text(item.get("summary")) or "Audit event recorded."
    created_at = _normalize_text(item.get("created_at")) or _utcnow_iso()
    verdict = _normalize_lower(item.get("verdict"))
    metadata = _safe_metadata(item.get("metadata"))

    detail_anchor = trace_id or request_id or event_id

    return AuditExplorerRow(
        event_id=event_id,
        created_at=created_at,
        event_type=event_type,
        severity=severity,
        summary=summary,
        actor_id=actor_id,
        session_id=session_id,
        request_id=request_id,
        trace_id=trace_id,
        integration_id=integration_id,
        verdict=verdict,
        metadata=metadata,
        badges=_build_badges(item),
        risk_flags=_build_risk_flags(item),
        detail_path=f"/ui/audit-log?selected={detail_anchor}",
    )


def _build_summary(
    *,
    items: list[dict[str, Any]],
    total: int,
    active_filters: dict[str, str],
) -> AuditExplorerSummary:
    severity_counter = Counter(_normalize_lower(item.get("severity")) or "unknown" for item in items)
    verdict_counter = Counter(_normalize_lower(item.get("verdict")) or "none" for item in items)
    event_type_counter = Counter(_normalize_text(item.get("event_type")) or "unknown" for item in items)
    actor_counter = Counter(_normalize_text(item.get("actor_id")) for item in items if _normalize_text(item.get("actor_id")))
    integration_counter = Counter(_normalize_text(item.get("integration_id")) for item in items if _normalize_text(item.get("integration_id")))

    counts = AuditExplorerCounts(
        total_events=total,
        critical_events=severity_counter.get("critical", 0),
        high_severity_events=severity_counter.get("high", 0),
        blocked_events=verdict_counter.get("block", 0) + verdict_counter.get("blocked", 0),
        quarantined_events=verdict_counter.get("quarantine", 0),
        unique_actors=len(actor_counter),
        unique_sessions=len(
            {value for item in items if (value := _normalize_text(item.get("session_id")))},
        ),
        unique_traces=len(
            {value for item in items if (value := _normalize_text(item.get("trace_id")))},
        ),
        unique_integrations=len(integration_counter),
    )

    subtitle = "Search, filter, and triage security audit events across actors, requests, traces, and policy outcomes."
    if total == 0:
        subtitle = "No audit events matched the current filter set."

    return AuditExplorerSummary(
        title="Audit Explorer",
        subtitle=subtitle,
        generated_at=_utcnow_iso(),
        active_filters=active_filters,
        counts=counts,
        severity_breakdown=dict(sorted(severity_counter.items())),
        verdict_breakdown=dict(sorted(verdict_counter.items())),
        event_type_breakdown=dict(event_type_counter.most_common(10)),
        top_actors=[actor for actor, _ in actor_counter.most_common(5)],
        top_integrations=[integration for integration, _ in integration_counter.most_common(5)],
    )


@router.get("", response_model=AuditExplorerResponse, summary="Get Audit Explorer")
def get_audit_explorer(
    actor_id: str | None = Query(default=None),
    request_id: str | None = Query(default=None),
    trace_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    integration_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> AuditExplorerResponse:
    source_payload = get_audit_explorer_data()
    source_items = _extract_items(source_payload)
    available_filters = _collect_filter_options(source_items)

    active_filters = {
        key: value
        for key, value in {
            "actor_id": _normalize_text(actor_id),
            "request_id": _normalize_text(request_id),
            "trace_id": _normalize_text(trace_id),
            "event_type": _normalize_text(event_type),
            "severity": _normalize_lower(severity),
            "verdict": _normalize_lower(verdict),
            "integration_id": _normalize_text(integration_id),
        }.items()
        if value is not None
    }

    filtered_items = _apply_filters(
        source_items,
        actor_id=actor_id,
        request_id=request_id,
        trace_id=trace_id,
        event_type=event_type,
        severity=severity,
        verdict=verdict,
        integration_id=integration_id,
    )
    filtered_items = sorted(
        filtered_items,
        key=lambda item: (
            _severity_rank(item.get("severity")),
            _normalize_text(item.get("created_at")) or "",
        ),
    )

    safe_limit = _coerce_limit(limit)
    page_items = filtered_items[:safe_limit]
    rows = [_build_row(item) for item in page_items]

    notes = [
        "Audit explorer is optimized for operator triage and trace-linked investigation workflows.",
        "Filter options are derived from the live event set returned by the audit explorer data source.",
        "Detail links pivot into the audit log using trace, request, or event identifiers when available.",
        "Historical audit records may retain legacy warn, quarantine, or review labels; these are not current verdict options.",
    ]

    return AuditExplorerResponse(
        status="ok",
        service="ironclaw-security",
        timestamp=_utcnow_iso(),
        summary=_build_summary(
            items=filtered_items,
            total=len(filtered_items),
            active_filters=active_filters,
        ),
        filters=available_filters,
        items=rows,
        total=len(filtered_items),
        limit=safe_limit,
        has_more=len(filtered_items) > safe_limit,
        empty_state=("No audit events matched the current filters." if not rows else None),
        notes=notes,
    )
