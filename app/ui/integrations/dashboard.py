from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.incident_store import (
    IncidentStore,
    list_incidents,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)
from app.services.metrics_store import (
    MetricsStore,
    get_integration_latency_summary,
    get_integration_throughput_summary,
)


def _normalize_status(value: str | None) -> str:
    if not value:
        return "unknown"
    return value.strip().lower()


def _is_active_status(value: str | None) -> bool:
    return _normalize_status(value) in {"active", "enabled"}


def _health_state(
    *,
    fail_count: int,
    warn_count: int,
    open_incident_count: int,
    p95_latency_ms: float,
    error_count_1h: int,
) -> str:
    if fail_count > 0 or open_incident_count > 0:
        return "critical"
    if warn_count > 0 or error_count_1h > 0 or p95_latency_ms > 1000:
        return "warning"
    return "healthy"


def _governance_state(
    *,
    verified: bool,
    command_ready: bool,
    install_ready: bool,
    fail_count: int,
) -> str:
    if fail_count > 0:
        return "at-risk"
    checks = sum((verified, command_ready, install_ready))
    if checks >= 3:
        return "governed"
    if checks >= 1:
        return "partial"
    return "at-risk"


@dataclass(slots=True)
class DashboardKpi:
    key: str
    title: str
    value: int
    tone: str = "neutral"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "value": self.value,
            "tone": self.tone,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationDashboardItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    verified: bool
    health_state: str
    governance_state: str
    request_count_1h: int
    error_count_1h: int
    p95_latency_ms: float
    open_incident_count: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "verified": self.verified,
            "health_state": self.health_state,
            "governance_state": self.governance_state,
            "request_count_1h": self.request_count_1h,
            "error_count_1h": self.error_count_1h,
            "p95_latency_ms": self.p95_latency_ms,
            "open_incident_count": self.open_incident_count,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationDashboardView:
    title: str
    total: int
    kpis: list[DashboardKpi] = field(default_factory=list)
    items: list[IntegrationDashboardItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "kpis": [kpi.to_dict() for kpi in self.kpis],
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _count_open_incidents(
    *,
    integration_id: str,
    incident_store: IncidentStore,
) -> int:
    open_statuses = {"open", "acknowledged", "investigating"}
    total = 0
    for incident in list_incidents(incident_store):
        incident_integration_id = getattr(incident, "integration_id", None)
        if incident_integration_id != integration_id:
            continue
        if str(getattr(incident, "status", "")).strip().lower() in open_statuses:
            total += 1
    return total


def build_integration_dashboard_view(
    *,
    registry: IntegrationRegistry,
    metrics_store: MetricsStore,
    incident_store: IncidentStore,
    requested_by: str = "ui-dashboard",
) -> IntegrationDashboardView:
    records = list_integrations(registry)

    items: list[IntegrationDashboardItem] = []
    active_count = 0
    healthy_count = 0
    warning_count = 0
    critical_count = 0
    governed_count = 0

    for record in records:
        verification = verify_integration(
            registry,
            record.integration_id,
            strict=False,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        verified = bool(summary.get("verified", False))
        warn_count = int(summary.get("warn_count", 0))
        fail_count = int(summary.get("fail_count", 0))

        throughput = get_integration_throughput_summary(metrics_store, record.integration_id)
        latency = get_integration_latency_summary(metrics_store, record.integration_id)
        open_incident_count = _count_open_incidents(
            integration_id=record.integration_id,
            incident_store=incident_store,
        )

        status = getattr(record, "status", "unknown")
        if _is_active_status(status):
            active_count += 1

        health_state = _health_state(
            fail_count=fail_count,
            warn_count=warn_count,
            open_incident_count=open_incident_count,
            p95_latency_ms=float(getattr(latency, "p95_ms", 0.0)),
            error_count_1h=int(getattr(throughput, "errors_1h", 0)),
        )
        governance_state = _governance_state(
            verified=verified,
            command_ready=bool(getattr(record, "command_name", None)),
            install_ready=bool(getattr(record, "install_target", None)),
            fail_count=fail_count,
        )

        if health_state == "healthy":
            healthy_count += 1
        elif health_state == "warning":
            warning_count += 1
        else:
            critical_count += 1

        if governance_state == "governed":
            governed_count += 1

        items.append(
            IntegrationDashboardItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=status,
                verified=verified,
                health_state=health_state,
                governance_state=governance_state,
                request_count_1h=int(getattr(throughput, "requests_1h", 0)),
                error_count_1h=int(getattr(throughput, "errors_1h", 0)),
                p95_latency_ms=float(getattr(latency, "p95_ms", 0.0)),
                open_incident_count=open_incident_count,
                metadata={
                    "requested_by": requested_by,
                    "integration_type": getattr(record, "integration_type", "unknown"),
                },
            ),
        )

    items.sort(
        key=lambda item: (
            0 if item.health_state == "critical" else 1 if item.health_state == "warning" else 2,
            -item.open_incident_count,
            -item.error_count_1h,
            item.platform,
            item.slug,
        ),
    )

    kpis = [
        DashboardKpi(key="total", title="Total Integrations", value=len(items), tone="neutral"),
        DashboardKpi(key="active", title="Active", value=active_count, tone="info"),
        DashboardKpi(key="healthy", title="Healthy", value=healthy_count, tone="success"),
        DashboardKpi(key="warning", title="Warning", value=warning_count, tone="warning"),
        DashboardKpi(key="critical", title="Critical", value=critical_count, tone="danger"),
        DashboardKpi(key="governed", title="Governed", value=governed_count, tone="success"),
    ]

    return IntegrationDashboardView(
        title="Integration Dashboard",
        total=len(items),
        kpis=kpis,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
