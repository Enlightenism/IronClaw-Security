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

_ACTIVE_STATUSES = {"open", "acknowledged", "investigating"}
_CRITICAL_SEVERITIES = {"critical", "crit", "sev0", "sev1"}
_HIGH_SEVERITIES = {"high", "sev2"}
_BREACHED_SLA_STATES = {"breached", "overdue"}


@dataclass(slots=True)
class IntegrationIncidentItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    incident_count: int
    open_incident_count: int
    critical_incident_count: int
    high_incident_count: int
    breached_sla_count: int
    last_incident_at: str | None
    health: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "incident_count": self.incident_count,
            "open_incident_count": self.open_incident_count,
            "critical_incident_count": self.critical_incident_count,
            "high_incident_count": self.high_incident_count,
            "breached_sla_count": self.breached_sla_count,
            "last_incident_at": self.last_incident_at,
            "health": self.health,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationIncidentsView:
    title: str
    total: int
    impacted_count: int
    critical_count: int
    items: list[IntegrationIncidentItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "impacted_count": self.impacted_count,
            "critical_count": self.critical_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _normalize_status(value: str | None) -> str:
    if not value:
        return "unknown"
    return value.strip().lower()


def _normalize_severity(value: str | None) -> str:
    if not value:
        return "unknown"
    raw = value.strip().lower()
    if raw in _CRITICAL_SEVERITIES:
        return "critical"
    if raw in _HIGH_SEVERITIES:
        return "high"
    if raw in {"medium", "med", "sev3"}:
        return "medium"
    if raw in {"low", "sev4"}:
        return "low"
    return raw


def _integration_key(incident: Any) -> str | None:
    for attr in ("integration_id", "source_integration_id"):
        value = getattr(incident, attr, None)
        if value:
            return str(value)
    return None


def _incident_timestamp(incident: Any) -> str | None:
    for attr in ("updated_at", "opened_at", "created_at"):
        value = getattr(incident, attr, None)
        if value is None:
            continue
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value)
    return None


def _sla_state(incident: Any) -> str:
    for attr in ("sla_state", "sla_status"):
        value = getattr(incident, attr, None)
        if value:
            return str(value).strip().lower()
    return "unknown"


def _health_for_counts(
    *,
    open_incident_count: int,
    critical_incident_count: int,
    breached_sla_count: int,
) -> str:
    if critical_incident_count > 0 or breached_sla_count > 0:
        return "critical"
    if open_incident_count > 0:
        return "degraded"
    return "healthy"


def build_integration_incidents_view(
    *,
    registry: IntegrationRegistry,
    incident_store: IncidentStore,
    requested_by: str = "ui-integrations-incidents",
) -> IntegrationIncidentsView:
    integrations = list_integrations(registry)
    incidents = list_incidents(incident_store)

    incident_map: dict[str, list[Any]] = {}
    for incident in incidents:
        key = _integration_key(incident)
        if not key:
            continue
        incident_map.setdefault(key, []).append(incident)

    items: list[IntegrationIncidentItem] = []
    impacted_count = 0
    critical_count = 0

    for integration in integrations:
        linked_incidents = incident_map.get(integration.integration_id, [])

        open_incident_count = 0
        critical_incident_count = 0
        high_incident_count = 0
        breached_sla_count = 0
        last_incident_at: str | None = None

        for incident in linked_incidents:
            status = _normalize_status(getattr(incident, "status", None))
            severity = _normalize_severity(getattr(incident, "severity", None))
            sla_state = _sla_state(incident)
            timestamp = _incident_timestamp(incident)

            if status in _ACTIVE_STATUSES:
                open_incident_count += 1
            if severity == "critical":
                critical_incident_count += 1
            elif severity == "high":
                high_incident_count += 1
            if sla_state in _BREACHED_SLA_STATES:
                breached_sla_count += 1
            if timestamp and (last_incident_at is None or timestamp > last_incident_at):
                last_incident_at = timestamp

        health = _health_for_counts(
            open_incident_count=open_incident_count,
            critical_incident_count=critical_incident_count,
            breached_sla_count=breached_sla_count,
        )

        if incident_count := len(linked_incidents):
            impacted_count += 1
        if critical_incident_count > 0 or breached_sla_count > 0:
            critical_count += 1

        items.append(
            IntegrationIncidentItem(
                integration_id=integration.integration_id,
                slug=integration.slug,
                name=integration.name,
                platform=integration.platform,
                status=integration.status,
                incident_count=incident_count,
                open_incident_count=open_incident_count,
                critical_incident_count=critical_incident_count,
                high_incident_count=high_incident_count,
                breached_sla_count=breached_sla_count,
                last_incident_at=last_incident_at,
                health=health,
                metadata={
                    "requested_by": requested_by,
                },
            )
        )

    items.sort(
        key=lambda item: (
            0 if item.health == "critical" else 1 if item.health == "degraded" else 2,
            -item.open_incident_count,
            -item.critical_incident_count,
            item.slug,
        )
    )

    return IntegrationIncidentsView(
        title="Integration Incidents",
        total=len(items),
        impacted_count=impacted_count,
        critical_count=critical_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )