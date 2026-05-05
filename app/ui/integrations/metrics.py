from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.dependencies import get_integration_registry
from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)
from app.services.incident_store import (
    IncidentStore,
    list_incidents,
)
from app.services.metrics_store import (
    MetricsStore,
    get_integration_latency_summary,
    get_integration_throughput_summary,
)


router = APIRouter(
    prefix="/ui/integrations",
    tags=["integration-metrics"],
)


@dataclass(slots=True)
class IntegrationMetricSnapshot:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str

    request_count_1m: int
    request_count_1h: int
    request_count_24h: int

    error_count_1m: int
    error_count_1h: int
    error_count_24h: int

    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float

    open_incident_count: int
    critical_incident_count: int

    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "request_count_1m": self.request_count_1m,
            "request_count_1h": self.request_count_1h,
            "request_count_24h": self.request_count_24h,
            "error_count_1m": self.error_count_1m,
            "error_count_1h": self.error_count_1h,
            "error_count_24h": self.error_count_24h,
            "p50_latency_ms": self.p50_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "p99_latency_ms": self.p99_latency_ms,
            "open_incident_count": self.open_incident_count,
            "critical_incident_count": self.critical_incident_count,
            "metadata": dict(self.metadata),
        }


class IntegrationMetricView(BaseModel):
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str

    request_count_1m: int
    request_count_1h: int
    request_count_24h: int

    error_count_1m: int
    error_count_1h: int
    error_count_24h: int

    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float

    open_incident_count: int
    critical_incident_count: int

    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationMetricsResponse(BaseModel):
    generated_at: str
    total: int
    active_count: int
    degraded_count: int
    items: list[IntegrationMetricView] = Field(default_factory=list)


def _is_active_status(status: str | None) -> bool:
    if not status:
        return False
    return status.lower() in {"active", "enabled"}


def _count_incidents_for_integration(
    *,
    integration_id: str,
    incident_store: IncidentStore,
) -> tuple[int, int]:
    open_count = 0
    critical_count = 0

    incidents = list_incidents(incident_store)
    for incident in incidents:
        incident_integration_id = getattr(incident, "integration_id", None)
        if incident_integration_id != integration_id:
            continue

        status = str(getattr(incident, "status", "")).lower()
        severity = str(getattr(incident, "severity", "")).lower()

        if status in {"open", "acknowledged", "investigating"}:
            open_count += 1

        if severity in {"critical", "crit", "sev0", "sev1"}:
            critical_count += 1

    return open_count, critical_count


def _build_metric_snapshot(
    *,
    registry: IntegrationRegistry,
    metrics_store: MetricsStore,
    incident_store: IncidentStore,
) -> list[IntegrationMetricSnapshot]:
    integrations = list_integrations(registry)

    snapshots: list[IntegrationMetricSnapshot] = []
    for record in integrations:
        latency = get_integration_latency_summary(metrics_store, record.integration_id)
        throughput = get_integration_throughput_summary(metrics_store, record.integration_id)
        open_incidents, critical_incidents = _count_incidents_for_integration(
            integration_id=record.integration_id,
            incident_store=incident_store,
        )

        snapshots.append(
            IntegrationMetricSnapshot(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=getattr(record, "status", "unknown"),
                request_count_1m=throughput.requests_1m,
                request_count_1h=throughput.requests_1h,
                request_count_24h=throughput.requests_24h,
                error_count_1m=throughput.errors_1m,
                error_count_1h=throughput.errors_1h,
                error_count_24h=throughput.errors_24h,
                p50_latency_ms=latency.p50_ms,
                p95_latency_ms=latency.p95_ms,
                p99_latency_ms=latency.p99_ms,
                open_incident_count=open_incidents,
                critical_incident_count=critical_incidents,
                metadata={
                    "rate_window_seconds": throughput.window_seconds,
                },
            )
        )

    return snapshots


def _snapshot_to_view(snapshot: IntegrationMetricSnapshot) -> IntegrationMetricView:
    return IntegrationMetricView(**snapshot.to_dict())


@router.get("/metrics", response_model=IntegrationMetricsResponse)
def get_integration_metrics() -> IntegrationMetricsResponse:
    registry = get_integration_registry()
    metrics_store = MetricsStore.current()
    incident_store = IncidentStore.current()

    snapshots = _build_metric_snapshot(
        registry=registry,
        metrics_store=metrics_store,
        incident_store=incident_store,
    )

    active_count = sum(
        1 for snap in snapshots if _is_active_status(snap.status)
    )
    degraded_count = sum(
        1
        for snap in snapshots
        if snap.critical_incident_count > 0 or snap.error_count_1h > 0
    )

    snapshots.sort(
        key=lambda s: (
            -s.critical_incident_count,
            -s.error_count_1h,
            -s.request_count_1h,
            s.slug,
        )
    )

    items = [_snapshot_to_view(s) for s in snapshots]

    return IntegrationMetricsResponse(
        generated_at=datetime.now(timezone.utc).isoformat(),
        total=len(items),
        active_count=active_count,
        degraded_count=degraded_count,
        items=items,
    )