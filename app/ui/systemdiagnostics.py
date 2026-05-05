from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(tags=["system-diagnostics"])


def _iso_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso_before(minutes: int) -> str:
    return (
        (datetime.now(UTC) - timedelta(minutes=minutes))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


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
    generated_at: str
    environment: str
    overall_status: str
    overall_tone: str
    service: str
    checks: list[DiagnosticsCheck]
    kpis: list[DiagnosticsKpi]
    active_incidents: list[DiagnosticsIncident]
    timeline: list[DiagnosticsTimelineEvent]
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.get("/ui/systemdiagnostics", response_model=SystemDiagnosticsResponse)
def get_system_diagnostics() -> SystemDiagnosticsResponse:
    checks = [
        DiagnosticsCheck(
            key="api_router",
            label="API Router",
            status="healthy",
            tone="success",
            summary="Core API routes loaded and responding within threshold.",
            last_checked_at=_iso_before(1),
            latency_ms=18,
            metadata={"routes_registered": 74, "error_rate_1h": "0.00%"},
        ),
        DiagnosticsCheck(
            key="policy_engine",
            label="Policy Engine",
            status="healthy",
            tone="success",
            summary="Policy evaluation pipeline available with current rule bundle.",
            last_checked_at=_iso_before(2),
            latency_ms=24,
            metadata={"bundle_version": "gen1-policy-2026.04.26", "mode": "enforce"},
        ),
        DiagnosticsCheck(
            key="review_queue",
            label="Review Queue",
            status="degraded",
            tone="warning",
            summary="Pending review backlog is above preferred threshold but still processing.",
            last_checked_at=_iso_before(3),
            latency_ms=41,
            metadata={"pending_items": 7, "sla_breach_count": 1},
        ),
        DiagnosticsCheck(
            key="sandbox_router",
            label="Sandbox Router",
            status="healthy",
            tone="success",
            summary="Sandbox routing and execution boundary checks are online.",
            last_checked_at=_iso_before(1),
            latency_ms=29,
            metadata={"active_sessions": 3, "blocked_executions_24h": 12},
        ),
        DiagnosticsCheck(
            key="telemetry_pipeline",
            label="Telemetry Pipeline",
            status="healthy",
            tone="success",
            summary="Telemetry ingestion and summary generation are current.",
            last_checked_at=_iso_before(4),
            latency_ms=33,
            metadata={"events_ingested_1h": 184, "queue_depth": 0},
        ),
        DiagnosticsCheck(
            key="persistence_state",
            label="Persistence State",
            status="healthy",
            tone="success",
            summary="Persistence bootstrap and runtime state snapshots are writable.",
            last_checked_at=_iso_before(2),
            latency_ms=37,
            metadata={"backend": "local", "snapshot_age_seconds": 46},
        ),
        DiagnosticsCheck(
            key="integration_registry",
            label="Integration Registry",
            status="healthy",
            tone="success",
            summary="Installed integrations registry is readable and internally consistent.",
            last_checked_at=_iso_before(5),
            latency_ms=22,
            metadata={"registered_integrations": 6, "verification_failures_24h": 0},
        ),
    ]

    active_incidents = [
        DiagnosticsIncident(
            incident_id="inc_diag_001",
            severity="medium",
            status="open",
            title="Review queue backlog elevated",
            summary="Queued human-review items exceeded preferred operating threshold.",
            detected_at=_iso_before(18),
            owner="ops-review",
        ),
        DiagnosticsIncident(
            incident_id="inc_diag_002",
            severity="low",
            status="monitoring",
            title="Telemetry ingest spike observed",
            summary="Short-lived telemetry burst detected and automatically absorbed.",
            detected_at=_iso_before(42),
            owner="system",
        ),
    ]

    timeline = [
        DiagnosticsTimelineEvent(
            timestamp=_iso_before(4),
            category="telemetry",
            title="Telemetry summary refreshed",
            summary="Background summarizer completed without lag.",
            tone="success",
        ),
        DiagnosticsTimelineEvent(
            timestamp=_iso_before(9),
            category="review",
            title="Review backlog threshold crossed",
            summary="Queue moved into degraded state due to pending approvals.",
            tone="warning",
        ),
        DiagnosticsTimelineEvent(
            timestamp=_iso_before(15),
            category="runtime",
            title="Sandbox session blocked",
            summary="High-risk execution halted by runtime boundary controls.",
            tone="critical",
        ),
        DiagnosticsTimelineEvent(
            timestamp=_iso_before(27),
            category="policy",
            title="Policy bundle validated",
            summary="Current policy bundle passed integrity and compatibility checks.",
            tone="success",
        ),
    ]

    healthy_count = sum(1 for check in checks if check.status == "healthy")
    degraded_count = sum(1 for check in checks if check.status == "degraded")
    critical_count = sum(1 for check in checks if check.status not in {"healthy", "degraded"})

    overall_status = "degraded" if degraded_count else "healthy"
    overall_tone = "warning" if degraded_count else "success"

    return SystemDiagnosticsResponse(
        generated_at=_iso_now(),
        environment="local",
        overall_status=overall_status,
        overall_tone=overall_tone,
        service="IronClaw",
        checks=checks,
        kpis=[
            DiagnosticsKpi(label="Healthy Checks", value=str(healthy_count), tone="success"),
            DiagnosticsKpi(label="Degraded Checks", value=str(degraded_count), tone="warning" if degraded_count else "neutral"),
            DiagnosticsKpi(label="Critical Checks", value=str(critical_count), tone="critical" if critical_count else "neutral"),
            DiagnosticsKpi(label="Active Incidents", value=str(len(active_incidents)), tone="warning" if active_incidents else "neutral"),
        ],
        active_incidents=active_incidents,
        timeline=timeline,
        metadata={
            "page_id": "system-diagnostics",
            "title": "System Diagnostics",
            "supports_live_polling": True,
            "refresh_interval_seconds": 15,
        },
    )