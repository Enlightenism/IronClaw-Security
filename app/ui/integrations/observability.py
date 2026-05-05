from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.dependencies import get_integration_registry
from app.services.incident_store import (
    IncidentStore,
    list_incidents,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)
from app.services.metrics_store import (
    MetricsStore,
    get_integration_latency_summary,
    get_integration_throughput_summary,
)


@dataclass(slots=True)
class IntegrationObservabilityItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str

    request_rate_1m: float
    error_rate_1m: float
    p95_latency_ms: float

    open_incident_count: int
    recent_incident_summaries: list[str] = field(default_factory=list)

    last_activity_at: str | None = None
    observability_score: int = 0

    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "request_rate_1m": self.request_rate_1m,
            "error_rate_1m": self.error_rate_1m,
            "p95_latency_ms": self.p95_latency_ms,
            "open_incident_count": self.open_incident_count,
            "recent_incident_summaries": list(self.recent_incident_summaries),
            "last_activity_at": self.last_activity_at,
            "observability_score": self.observability_score,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationObservabilityView:
    title: str
    generated_at: str
    total: int
    active_count: int
    degraded_count: int
    items: list[IntegrationObservabilityItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "total": self.total,
            "active_count": self.active_count,
            "degraded_count": self.degraded_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _is_active_status(value: str | None) -> bool:
    if not value:
        return False
    return value.strip().lower() in {"active", "enabled"}


def _observability_score(
    *,
    request_rate_1m: float,
    error_rate_1m: float,
    p95_latency_ms: float,
    open_incident_count: int,
) -> int:
    score = 100

    # Penalize high error rates.
    if error_rate_1m > 0:
        score -= min(int(error_rate_1m * 50), 40)

    # Penalize high latency.
    if p95_latency_ms > 0:
        if p95_latency_ms > 2000:
            score -= 30
        elif p95_latency_ms > 1000:
            score -= 20
        elif p95_latency_ms > 500:
            score -= 10

    # Penalize open incidents.
    if open_incident_count > 0:
        score -= min(open_incident_count * 10, 40)

    # Clamp between 0 and 100.
    return max(0, min(score, 100))


def _index_incidents_by_integration(
    incident_store: IncidentStore,
) -> dict[str, list[Any]]:
    incidents_by_integration: dict[str, list[Any]] = {}
    for incident in list_incidents(incident_store):
        integration_id = getattr(incident, "integration_id", None)
        if not integration_id:
            continue
        incidents_by_integration.setdefault(integration_id, []).append(incident)

    # Sort each integration's incidents newest-first by created_at / updated_at.
    for integration_id, incidents in incidents_by_integration.items():
        incidents.sort(
            key=lambda inc: str(
                getattr(inc, "updated_at", getattr(inc, "created_at", ""))
            ),
            reverse=True,
        )

    return incidents_by_integration


def _summarize_recent_incidents(incidents: list[Any], limit: int = 3) -> list[str]:
    summaries: list[str] = []
    for incident in incidents[:limit]:
        status = str(getattr(incident, "status", "unknown")).lower()
        severity = str(getattr(incident, "severity", "unknown")).lower()
        title = str(getattr(incident, "title", "") or "").strip()
        if title:
            summaries.append(f"[{severity}/{status}] {title}")
        else:
            summaries.append(f"[{severity}/{status}] incident {getattr(incident, 'incident_id', 'unknown')}")
    return summaries


def build_integration_observability_view() -> IntegrationObservabilityView:
    registry: IntegrationRegistry = get_integration_registry()
    metrics_store = MetricsStore.current()
    incident_store = IncidentStore.current()

    integrations = list_integrations(registry)
    incidents_by_integration = _index_incidents_by_integration(incident_store)

    items: list[IntegrationObservabilityItem] = []
    active_count = 0
    degraded_count = 0

    for record in integrations:
        status = getattr(record, "status", "unknown")
        if _is_active_status(status):
            active_count += 1

        latency = get_integration_latency_summary(metrics_store, record.integration_id)
        throughput = get_integration_throughput_summary(metrics_store, record.integration_id)

        # Derive simple rates from the 1-minute window.
        request_rate_1m = float(getattr(throughput, "requests_1m", 0))
        error_rate_1m = float(getattr(throughput, "errors_1m", 0))

        p95_latency_ms = float(getattr(latency, "p95_ms", 0.0))

        integration_incidents = incidents_by_integration.get(record.integration_id, [])
        open_incident_count = sum(
            1
            for inc in integration_incidents
            if str(getattr(inc, "status", "")).lower()
            in {"open", "acknowledged", "investigating"}
        )

        if open_incident_count > 0 or error_rate_1m > 0 or p95_latency_ms > 1000:
            degraded_count += 1

        recent_incident_summaries = _summarize_recent_incidents(integration_incidents)

        last_activity_at = str(
            getattr(
                record,
                "updated_at",
                getattr(record, "created_at", ""),
            )
        )

        observability_score = _observability_score(
            request_rate_1m=request_rate_1m,
            error_rate_1m=error_rate_1m,
            p95_latency_ms=p95_latency_ms,
            open_incident_count=open_incident_count,
        )

        items.append(
            IntegrationObservabilityItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=status,
                request_rate_1m=request_rate_1m,
                error_rate_1m=error_rate_1m,
                p95_latency_ms=p95_latency_ms,
                open_incident_count=open_incident_count,
                recent_incident_summaries=recent_incident_summaries,
                last_activity_at=last_activity_at,
                observability_score=observability_score,
                metadata={
                    "requested_by": "ui-observability",
                    "rate_window_seconds": getattr(throughput, "window_seconds", None),
                },
            )
        )

    items.sort(
        key=lambda item: (
            item.observability_score,
            -item.open_incident_count,
            -item.error_rate_1m,
            item.slug,
        ),
        reverse=True,
    )

    return IntegrationObservabilityView(
        title="Integration Observability",
        generated_at=datetime.now(timezone.utc).isoformat(),
        total=len(items),
        active_count=active_count,
        degraded_count=degraded_count,
        items=items,
        metadata={
            "requested_by": "ui-observability",
        },
    )