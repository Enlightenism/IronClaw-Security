from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key


router = APIRouter(
    prefix="/guard/audit",
    tags=["audit-log"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class AuditEventView(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    severity: str
    action_type: str
    target: str
    client_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    review_id: str | None = None
    execution_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


_SAMPLE_AUDIT_EVENTS: list[AuditEventView] = [
    AuditEventView(
        event_id="audit_001",
        timestamp=_utc_now_iso(),
        event_type="execution_allowed",
        severity="info",
        action_type="http_fetch",
        target="https://example.com",
        client_id="client-alpha",
        session_id="sess-001",
        request_id="req_001",
        trace_id="trace_001",
        review_id=None,
        execution_id="exec_001",
        details={
            "policy_verdict": "allow",
            "reason": "Public fetch allowed by policy.",
        },
    ),
    AuditEventView(
        event_id="audit_002",
        timestamp=_utc_now_iso(),
        event_type="execution_denied",
        severity="critical",
        action_type="shell_execute",
        target="rm -rf /workspace",
        client_id="client-beta",
        session_id="sess-002",
        request_id="req_002",
        trace_id="trace_002",
        review_id="review_001",
        execution_id="exec_002",
        details={
            "policy_verdict": "block",
            "reason": "Destructive command blocked by runtime boundary.",
        },
    ),
    AuditEventView(
        event_id="audit_003",
        timestamp=_utc_now_iso(),
        event_type="execution_review",
        severity="warning",
        action_type="http_fetch",
        target="https://unknown.example/payload",
        client_id="client-gamma",
        session_id="sess-003",
        request_id="req_003",
        trace_id="trace_003",
        review_id="review_002",
        execution_id="exec_003",
        details={
            "policy_verdict": "review",
            "reason": "Untrusted external content escalated for review.",
        },
    ),
]


class TelemetrySummaryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total_events: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    event_type_counts: dict[str, int] = Field(default_factory=dict)


def _filter_events(
    *,
    session_id: str | None = None,
    actor_id: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
) -> list[AuditEventView]:
    items = list(_SAMPLE_AUDIT_EVENTS)

    if session_id is not None:
        items = [item for item in items if item.session_id == session_id]

    if actor_id is not None:
        items = [item for item in items if item.client_id == actor_id]

    if request_id is not None:
        items = [item for item in items if item.request_id == request_id]

    if trace_id is not None:
        items = [item for item in items if item.trace_id == trace_id]

    return items


@router.get("/events", response_model=list[AuditEventView])
def get_audit_events(
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AuditEventView]:
    return list(_SAMPLE_AUDIT_EVENTS[:limit])


@router.get("/events/by-session/{session_id}", response_model=list[AuditEventView])
def get_audit_events_by_session(
    session_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AuditEventView]:
    return _filter_events(session_id=session_id)[:limit]


@router.get("/events/by-actor/{actor_id}", response_model=list[AuditEventView])
def get_audit_events_by_actor(
    actor_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AuditEventView]:
    return _filter_events(actor_id=actor_id)[:limit]


@router.get("/events/by-request/{request_id}", response_model=list[AuditEventView])
def get_audit_events_by_request(request_id: str) -> list[AuditEventView]:
    return _filter_events(request_id=request_id)


@router.get("/events/by-trace/{trace_id}", response_model=list[AuditEventView])
def get_audit_events_by_trace(trace_id: str) -> list[AuditEventView]:
    return _filter_events(trace_id=trace_id)


@router.get("/telemetry/events", response_model=list[AuditEventView])
def get_telemetry_events(
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AuditEventView]:
    return list(_SAMPLE_AUDIT_EVENTS[:limit])


@router.get("/telemetry/summary", response_model=TelemetrySummaryResponse)
def get_telemetry_summary(
    limit: int = Query(default=500, ge=1, le=5000),
) -> TelemetrySummaryResponse:
    items = list(_SAMPLE_AUDIT_EVENTS[:limit])

    severity_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}

    for item in items:
        severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1
        event_type_counts[item.event_type] = event_type_counts.get(item.event_type, 0) + 1

    return TelemetrySummaryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total_events=len(items),
        severity_counts=severity_counts,
        event_type_counts=event_type_counts,
    )