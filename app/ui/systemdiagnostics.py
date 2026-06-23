from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(tags=["system-diagnostics"])


class DiagnosticsKpi(BaseModel):
    label: str
    value: str
    tone: str = "neutral"


class DiagnosticsCheck(BaseModel):
    key: str
    label: str
    status: str
    tone: str
    summary: str
    last_checked_at: str
    latency_ms: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DiagnosticsIncident(BaseModel):
    incident_id: str
    severity: str
    status: str
    title: str
    summary: str
    detected_at: str
    owner: str | None = None


class DiagnosticsTimelineEvent(BaseModel):
    timestamp: str
    category: str
    title: str
    summary: str
    tone: str


class SystemDiagnosticsResponse(BaseModel):
    title: str
    environment: str
    overall_status: str
    overall_tone: str
    service: str
    generated_at: str
    checks: list[DiagnosticsCheck]
    kpis: list[DiagnosticsKpi]
    active_incidents: list[DiagnosticsIncident]
    timeline: list[DiagnosticsTimelineEvent]
    actions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


_CHECKS: list[DiagnosticsCheck] = [
    DiagnosticsCheck(
        key="api_router",
        label="API Router",
        status="healthy",
        tone="success",
        summary="Core API routes loaded and responding within threshold.",
        last_checked_at="2026-01-01T00:00:00Z",
        latency_ms=18,
        metadata={"routes_registered": 74, "error_rate_1h": "0.00%"},
    ),
    DiagnosticsCheck(
        key="policy_engine",
        label="Policy Engine",
        status="healthy",
        tone="success",
        summary="Policy evaluation pipeline available with current rule bundle.",
        last_checked_at="2026-01-01T00:00:00Z",
        latency_ms=24,
        metadata={"bundle_version": "gen1-policy-2026.04.26", "mode": "enforce"},
    ),
    DiagnosticsCheck(
        key="review_queue",
        label="Review Queue",
        status="degraded",
        tone="warning",
        summary="Pending review backlog is above preferred threshold but still processing.",
        last_checked_at="2026-01-01T00:00:00Z",
        latency_ms=41,
        metadata={"pending_items": 7, "sla_breach_count": 1},
    ),
    DiagnosticsCheck(
        key="sandbox_router",
        label="Sandbox Router",
        status="healthy",
        tone="success",
        summary="Sandbox routing and execution boundary checks are online.",
        last_checked_at="2026-01-01T00:00:00Z",
        latency_ms=29,
        metadata={"active_sessions": 3, "blocked_executions_24h": 12},
    ),
    DiagnosticsCheck(
        key="telemetry_pipeline",
        label="Telemetry Pipeline",
        status="healthy",
        tone="success",
        summary="Telemetry ingestion and summary generation are current.",
        last_checked_at="2026-01-01T00:00:00Z",
        latency_ms=33,
        metadata={"events_ingested_1h": 184, "queue_depth": 0},
    ),
    DiagnosticsCheck(
        key="persistence_state",
        label="Persistence State",
        status="healthy",
        tone="success",
        summary="Persistence bootstrap and runtime state snapshots are writable.",
        last_checked_at="2026-01-01T00:00:00Z",
        latency_ms=37,
        metadata={"backend": "local", "snapshot_age_seconds": 46},
    ),
    DiagnosticsCheck(
        key="integration_registry",
        label="Integration Registry",
        status="healthy",
        tone="success",
        summary="Installed integrations registry is readable and internally consistent.",
        last_checked_at="2026-01-01T00:00:00Z",
        latency_ms=22,
        metadata={"registered_integrations": 6, "verification_failures_24h": 0},
    ),
]

_INCIDENTS: list[DiagnosticsIncident] = [
    DiagnosticsIncident(
        incident_id="inc_diag_001",
        severity="medium",
        status="open",
        title="Review queue backlog elevated",
        summary="Queued human-review items exceeded preferred operating threshold.",
        detected_at="2026-06-23T10:14:00Z",
        owner="ops-review",
    ),
    DiagnosticsIncident(
        incident_id="inc_diag_002",
        severity="low",
        status="monitoring",
        title="Telemetry ingest spike observed",
        summary="Short-lived telemetry burst detected and automatically absorbed.",
        detected_at="2026-06-23T11:02:00Z",
        owner="system",
    ),
]

_TIMELINE: list[DiagnosticsTimelineEvent] = [
    DiagnosticsTimelineEvent(
        timestamp="2026-06-23T08:00:00Z",
        category="telemetry",
        title="Telemetry summary refreshed",
        summary="Background summarizer completed without lag.",
        tone="success",
    ),
    DiagnosticsTimelineEvent(
        timestamp="2026-06-23T09:45:00Z",
        category="review",
        title="Review backlog threshold crossed",
        summary="Queue moved into degraded state due to pending approvals.",
        tone="warning",
    ),
    DiagnosticsTimelineEvent(
        timestamp="2026-06-23T10:14:00Z",
        category="runtime",
        title="Sandbox session blocked",
        summary="High-risk execution halted by runtime boundary controls.",
        tone="critical",
    ),
    DiagnosticsTimelineEvent(
        timestamp="2026-06-23T11:30:00Z",
        category="policy",
        title="Policy bundle validated",
        summary="Current policy bundle passed integrity and compatibility checks.",
        tone="success",
    ),
]

_healthy_count = sum(1 for c in _CHECKS if c.status == "healthy")
_degraded_count = sum(1 for c in _CHECKS if c.status == "degraded")
_critical_count = sum(1 for c in _CHECKS if c.status not in {"healthy", "degraded"})

_RESPONSE = SystemDiagnosticsResponse(
    title="System Diagnostics",
    environment="local",
    overall_status="degraded" if _degraded_count else "healthy",
    overall_tone="warning" if _degraded_count else "success",
    service="IronClaw",
    generated_at="2026-06-23T00:00:00Z",
    checks=_CHECKS,
    kpis=[
        DiagnosticsKpi(label="Healthy Checks", value=str(_healthy_count), tone="success"),
        DiagnosticsKpi(label="Degraded Checks", value=str(_degraded_count), tone="warning" if _degraded_count else "neutral"),
        DiagnosticsKpi(label="Critical Checks", value=str(_critical_count), tone="critical" if _critical_count else "neutral"),
        DiagnosticsKpi(label="Active Incidents", value=str(len(_INCIDENTS)), tone="warning" if _INCIDENTS else "neutral"),
    ],
    active_incidents=_INCIDENTS,
    timeline=_TIMELINE,
    actions=[],
    metadata={
        "page_id": "system-diagnostics",
        "title": "System Diagnostics",
        "supports_live_polling": True,
        "refresh_interval_seconds": 15,
    },
)


@router.get("/ui/systemdiagnostics", response_model=SystemDiagnosticsResponse)
def get_system_diagnostics() -> SystemDiagnosticsResponse:
    return _RESPONSE
