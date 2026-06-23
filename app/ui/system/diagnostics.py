from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui",
    tags=["system-diagnostics"],
)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class DiagnosticCheckItem(BaseModel):
    key: str
    label: str
    status: str
    tone: str
    summary: str
    last_checked_at: str
    latency_ms: int | None = None
    metadata: dict = Field(default_factory=dict)


class KpiItem(BaseModel):
    label: str
    value: str
    tone: str


class IncidentItem(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    detected_at: str
    owner: str | None = None


class TimelineEvent(BaseModel):
    event_id: str
    timestamp: str
    category: str
    tone: str
    description: str


class SystemDiagnosticsResponse(BaseModel):
    title: str
    environment: str
    overall_status: str
    overall_tone: str
    service: str
    generated_at: str
    checks: list[DiagnosticCheckItem] = Field(default_factory=list)
    kpis: list[KpiItem] = Field(default_factory=list)
    active_incidents: list[IncidentItem] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_checks() -> list[DiagnosticCheckItem]:
    ts = _now()
    return [
        DiagnosticCheckItem(
            key="api_router",
            label="API Router",
            status="healthy",
            tone="success",
            summary="Primary FastAPI router is responding to all registered routes.",
            last_checked_at=ts,
            latency_ms=18,
            metadata={"route_count": 142, "version": "1.0.0"},
        ),
        DiagnosticCheckItem(
            key="policy_engine",
            label="Policy Engine",
            status="healthy",
            tone="success",
            summary="Policy evaluation pipeline is processing verdicts within SLA.",
            last_checked_at=ts,
            latency_ms=24,
            metadata={"active_policies": 12, "eval_mode": "strict"},
        ),
        DiagnosticCheckItem(
            key="review_queue",
            label="Review Queue",
            status="degraded",
            tone="warning",
            summary="Review queue depth exceeds threshold; analyst backlog detected.",
            last_checked_at=ts,
            latency_ms=None,
            metadata={"queue_depth": 47, "threshold": 20},
        ),
        DiagnosticCheckItem(
            key="telemetry_pipeline",
            label="Telemetry Pipeline",
            status="healthy",
            tone="success",
            summary="Telemetry ingestion and forwarding are operating normally.",
            last_checked_at=ts,
            latency_ms=11,
            metadata={"events_per_minute": 320, "buffer_usage_pct": 14},
        ),
        DiagnosticCheckItem(
            key="audit_log",
            label="Audit Log",
            status="healthy",
            tone="success",
            summary="Audit log writes are completing within acceptable latency.",
            last_checked_at=ts,
            latency_ms=9,
            metadata={"log_backend": "supabase"},
        ),
    ]


def _build_active_incidents() -> list[IncidentItem]:
    return [
        IncidentItem(
            incident_id="inc_diag_001",
            title="Review queue backlog exceeding threshold",
            severity="high",
            status="investigating",
            detected_at="2026-06-23T10:14:00Z",
            owner="ops-team",
        ),
        IncidentItem(
            incident_id="inc_diag_002",
            title="Elevated policy eval latency on edge nodes",
            severity="medium",
            status="monitoring",
            detected_at="2026-06-23T11:02:00Z",
            owner=None,
        ),
    ]


def _build_timeline() -> list[TimelineEvent]:
    return [
        TimelineEvent(
            event_id="evt_diag_001",
            timestamp="2026-06-23T08:00:00Z",
            category="deployment",
            tone="success",
            description="IronClaw v1.4.2 deployed successfully to production.",
        ),
        TimelineEvent(
            event_id="evt_diag_002",
            timestamp="2026-06-23T09:45:00Z",
            category="alert",
            tone="warning",
            description="Review queue depth crossed warning threshold (47 items).",
        ),
        TimelineEvent(
            event_id="evt_diag_003",
            timestamp="2026-06-23T10:14:00Z",
            category="incident",
            tone="critical",
            description="Incident inc_diag_001 opened: review queue backlog escalated.",
        ),
        TimelineEvent(
            event_id="evt_diag_004",
            timestamp="2026-06-23T11:30:00Z",
            category="recovery",
            tone="success",
            description="API router health confirmed after rolling config refresh.",
        ),
    ]


def _derive_overall(checks: list[DiagnosticCheckItem]) -> tuple[str, str]:
    if any(c.status == "critical" for c in checks):
        return "critical", "critical"
    if any(c.status == "degraded" for c in checks):
        return "degraded", "warning"
    return "healthy", "success"


def _build_kpis(
    checks: list[DiagnosticCheckItem],
    incidents: list[IncidentItem],
) -> list[KpiItem]:
    healthy_count = sum(1 for c in checks if c.status == "healthy")
    degraded_count = sum(1 for c in checks if c.status == "degraded")
    return [
        KpiItem(
            label="Healthy Checks",
            value=str(healthy_count),
            tone="success",
        ),
        KpiItem(
            label="Degraded Checks",
            value=str(degraded_count),
            tone="warning" if degraded_count > 0 else "success",
        ),
        KpiItem(
            label="Active Incidents",
            value=str(len(incidents)),
            tone="critical" if len(incidents) > 0 else "success",
        ),
    ]


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get("/systemdiagnostics", response_model=SystemDiagnosticsResponse)
def get_system_diagnostics() -> SystemDiagnosticsResponse:
    checks = _build_checks()
    incidents = _build_active_incidents()
    timeline = _build_timeline()
    overall_status, overall_tone = _derive_overall(checks)
    kpis = _build_kpis(checks, incidents)

    return SystemDiagnosticsResponse(
        title="System Diagnostics",
        environment="local",
        overall_status=overall_status,
        overall_tone=overall_tone,
        service="IronClaw",
        generated_at=_now(),
        checks=checks,
        kpis=kpis,
        active_incidents=incidents,
        timeline=timeline,
        metadata={
            "page_id": "system-diagnostics",
            "title": "System Diagnostics",
            "supports_live_polling": True,
            "refresh_interval_seconds": 30,
        },
    )
