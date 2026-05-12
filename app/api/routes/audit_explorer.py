from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/audit-explorer",
    tags=["audit-explorer"],
    dependencies=[Depends(require_api_key)],
)


AuditSeverity = Literal["low", "medium", "high", "critical"]
AuditCategory = Literal["policy", "incident", "quarantine", "review", "execution", "auth", "system"]
AuditOutcome = Literal["success", "warning", "blocked", "failure"]
ExportFormat = Literal["json", "csv"]


class AuditEventView(BaseModel):
    event_id: str
    timestamp: str
    severity: AuditSeverity
    category: AuditCategory
    action: str
    outcome: AuditOutcome
    actor_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class AuditKpiView(BaseModel):
    label: str
    value: int
    status: str = "neutral"


class AuditTimelinePoint(BaseModel):
    timestamp: str
    total_events: int
    blocked_events: int
    warning_events: int
    failure_events: int


class AuditFilterView(BaseModel):
    filter_key: str
    values: list[str] = Field(default_factory=list)


class AuditExplorerResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    applied_filters: dict[str, Any] = Field(default_factory=dict)
    kpis: list[AuditKpiView] = Field(default_factory=list)
    timeline: list[AuditTimelinePoint] = Field(default_factory=list)
    filters: list[AuditFilterView] = Field(default_factory=list)
    items: list[AuditEventView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AuditExportResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    export_format: ExportFormat
    total: int
    content_type: str
    filename: str
    content: str


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _seed_events() -> list[AuditEventView]:
    return [
        AuditEventView(
            event_id="aud-001",
            timestamp="2026-04-22T17:10:00Z",
            severity="high",
            category="policy",
            action="policy.threshold.block",
            outcome="blocked",
            actor_id="system:policy-engine",
            session_id="sess-1001",
            request_id="req-1001",
            trace_id="trace-1001",
            resource_type="policy",
            resource_id="ironclaw-default-policy",
            summary="Policy engine blocked a high-risk prompt bundle.",
            details={"verdict": "block", "risk_score": 92},
            tags=["policy", "prompt-injection", "block"],
        ),
        AuditEventView(
            event_id="aud-002",
            timestamp="2026-04-22T17:14:00Z",
            severity="critical",
            category="quarantine",
            action="quarantine.item.created",
            outcome="warning",
            actor_id="system:quarantine",
            session_id="sess-1002",
            request_id="req-1002",
            trace_id="trace-1002",
            resource_type="quarantine",
            resource_id="qtn-1002",
            summary="Suspicious tool output was isolated for review.",
            details={"status": "isolated", "risk_level": "critical"},
            tags=["quarantine", "tool-output", "sandbox"],
        ),
        AuditEventView(
            event_id="aud-003",
            timestamp="2026-04-22T17:20:00Z",
            severity="medium",
            category="incident",
            action="incident.status.updated",
            outcome="success",
            actor_id="analyst:ops-01",
            session_id="sess-1003",
            request_id="req-1003",
            trace_id="trace-1003",
            resource_type="incident",
            resource_id="inc-1003",
            summary="Incident moved from open to triaged.",
            details={"from": "open", "to": "triaged"},
            tags=["incident", "triage"],
        ),
        AuditEventView(
            event_id="aud-004",
            timestamp="2026-04-22T17:28:00Z",
            severity="medium",
            category="execution",
            action="execution.guard.allowed",
            outcome="success",
            actor_id="system:guard",
            session_id="sess-1004",
            request_id="req-1004",
            trace_id="trace-1004",
            resource_type="execution",
            resource_id="exec-1004",
            summary="Guarded execution completed under allow verdict.",
            details={"policy_verdict": "allow", "risk_score": 18},
            tags=["execution", "guard", "allow"],
        ),
        AuditEventView(
            event_id="aud-005",
            timestamp="2026-04-22T17:35:00Z",
            severity="high",
            category="auth",
            action="auth.api_key.denied",
            outcome="failure",
            actor_id="anonymous",
            session_id=None,
            request_id="req-1005",
            trace_id="trace-1005",
            resource_type="auth",
            resource_id="api-key",
            summary="Request denied because API key validation failed.",
            details={"reason": "invalid_api_key"},
            tags=["auth", "denied"],
        ),
        AuditEventView(
            event_id="aud-006",
            timestamp="2026-04-22T17:41:00Z",
            severity="low",
            category="system",
            action="system.health.snapshot",
            outcome="success",
            actor_id="system:health",
            session_id=None,
            request_id="req-1006",
            trace_id="trace-1006",
            resource_type="system",
            resource_id="health",
            summary="Operational health snapshot generated.",
            details={"live": True, "ready": True},
            tags=["system", "health"],
        ),
    ]


def _filter_events(
    events: list[AuditEventView],
    *,
    severity: AuditSeverity | None,
    category: AuditCategory | None,
    outcome: AuditOutcome | None,
    actor_id: str | None,
    request_id: str | None,
    trace_id: str | None,
    resource_id: str | None,
    search: str | None,
) -> list[AuditEventView]:
    filtered = list(events)

    if severity is not None:
        filtered = [event for event in filtered if event.severity == severity]
    if category is not None:
        filtered = [event for event in filtered if event.category == category]
    if outcome is not None:
        filtered = [event for event in filtered if event.outcome == outcome]
    if actor_id is not None:
        filtered = [event for event in filtered if event.actor_id == actor_id]
    if request_id is not None:
        filtered = [event for event in filtered if event.request_id == request_id]
    if trace_id is not None:
        filtered = [event for event in filtered if event.trace_id == trace_id]
    if resource_id is not None:
        filtered = [event for event in filtered if event.resource_id == resource_id]
    if search:
        needle = search.strip().lower()
        filtered = [
            event
            for event in filtered
            if needle in event.summary.lower()
            or needle in event.action.lower()
            or any(needle in tag.lower() for tag in event.tags)
        ]

    return filtered


def _build_kpis(events: list[AuditEventView]) -> list[AuditKpiView]:
    return [
        AuditKpiView(label="total_events", value=len(events)),
        AuditKpiView(label="blocked_events", value=sum(1 for item in events if item.outcome == "blocked"), status="alert"),
        AuditKpiView(label="warning_events", value=sum(1 for item in events if item.outcome == "warning"), status="warning"),
        AuditKpiView(label="failure_events", value=sum(1 for item in events if item.outcome == "failure"), status="critical"),
    ]


def _build_timeline(events: list[AuditEventView]) -> list[AuditTimelinePoint]:
    points: list[AuditTimelinePoint] = []
    for event in events:
        points.append(
            AuditTimelinePoint(
                timestamp=event.timestamp,
                total_events=1,
                blocked_events=1 if event.outcome == "blocked" else 0,
                warning_events=1 if event.outcome == "warning" else 0,
                failure_events=1 if event.outcome == "failure" else 0,
            )
        )
    return points


def _build_filters(events: list[AuditEventView]) -> list[AuditFilterView]:
    def unique(values: list[str | None]) -> list[str]:
        return sorted({value for value in values if value})

    return [
        AuditFilterView(filter_key="severity", values=unique([event.severity for event in events])),
        AuditFilterView(filter_key="category", values=unique([event.category for event in events])),
        AuditFilterView(filter_key="outcome", values=unique([event.outcome for event in events])),
        AuditFilterView(filter_key="actor_id", values=unique([event.actor_id for event in events])),
        AuditFilterView(filter_key="resource_id", values=unique([event.resource_id for event in events])),
    ]


def _build_export_content(events: list[AuditEventView], export_format: ExportFormat) -> tuple[str, str, str]:
    if export_format == "json":
        import json

        content = json.dumps([event.model_dump() for event in events], indent=2)
        return "application/json", "audit-export.json", content

    header = [
        "event_id",
        "timestamp",
        "severity",
        "category",
        "action",
        "outcome",
        "actor_id",
        "session_id",
        "request_id",
        "trace_id",
        "resource_type",
        "resource_id",
        "summary",
        "tags",
    ]
    lines = [",".join(header)]
    for event in events:
        row = [
            event.event_id,
            event.timestamp,
            event.severity,
            event.category,
            event.action,
            event.outcome,
            event.actor_id or "",
            event.session_id or "",
            event.request_id or "",
            event.trace_id or "",
            event.resource_type or "",
            event.resource_id or "",
            event.summary.replace(",", ";"),
            "|".join(event.tags),
        ]
        lines.append(",".join(row))
    return "text/csv", "audit-export.csv", "\n".join(lines)


@router.get("/", response_model=AuditExplorerResponse)
def read_audit_explorer(
    severity: AuditSeverity | None = Query(default=None),
    category: AuditCategory | None = Query(default=None),
    outcome: AuditOutcome | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    request_id: str | None = Query(default=None),
    trace_id: str | None = Query(default=None),
    resource_id: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
) -> AuditExplorerResponse:
    seeded = _seed_events()
    filtered = _filter_events(
        seeded,
        severity=severity,
        category=category,
        outcome=outcome,
        actor_id=actor_id,
        request_id=request_id,
        trace_id=trace_id,
        resource_id=resource_id,
        search=search,
    )

    return AuditExplorerResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(filtered),
        applied_filters={
            "severity": severity,
            "category": category,
            "outcome": outcome,
            "actor_id": actor_id,
            "request_id": request_id,
            "trace_id": trace_id,
            "resource_id": resource_id,
            "search": search,
        },
        kpis=_build_kpis(filtered),
        timeline=_build_timeline(filtered),
        filters=_build_filters(seeded),
        items=filtered,
        notes=[
            "This explorer currently serves seeded in-memory audit data.",
            "Next upgrade can connect these views to the persistent audit/event pipeline.",
        ],
    )


@router.get("/export", response_model=AuditExportResponse)
def export_audit_explorer(
    export_format: ExportFormat = Query(default="json"),
    severity: AuditSeverity | None = Query(default=None),
    category: AuditCategory | None = Query(default=None),
    outcome: AuditOutcome | None = Query(default=None),
) -> AuditExportResponse:
    seeded = _seed_events()
    filtered = _filter_events(
        seeded,
        severity=severity,
        category=category,
        outcome=outcome,
        actor_id=None,
        request_id=None,
        trace_id=None,
        resource_id=None,
        search=None,
    )
    content_type, filename, content = _build_export_content(filtered, export_format)

    return AuditExportResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        export_format=export_format,
        total=len(filtered),
        content_type=content_type,
        filename=filename,
        content=content,
    )