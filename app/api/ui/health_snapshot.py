from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter

from app.services.integrationregistry import get_integration_registry
from app.services.integrationtelemetry import get_integration_telemetry_service


router = APIRouter(prefix="/ui/health-snapshot", tags=["ui-health-snapshot"])


@router.get("")
def read_health_snapshot() -> dict[str, object]:
    registry = get_integration_registry()
    telemetry_service = get_integration_telemetry_service()

    integrations = registry.list_integrations()
    events = telemetry_service.list_events()

    healthy_statuses = {"available", "configured", "ready"}

    total_integrations = len(integrations)
    healthy_integrations = sum(
        1 for integration in integrations if integration.status in healthy_statuses
    )
    degraded_integrations = total_integrations - healthy_integrations
    total_events = len(events)
    warning_events = sum(1 for event in events if event.level == "warning")

    score = 100
    score -= degraded_integrations * 10
    score -= warning_events * 2
    score = max(score, 0)

    return {
        "service": "ironclaw-security",
        "environment": "local",
        "generated_at": datetime.now(UTC).isoformat(),
        "health_score": score,
        "status": (
            "healthy" if degraded_integrations == 0 and warning_events == 0 else "degraded"
        ),
        "totals": {
            "integrations": total_integrations,
            "healthy_integrations": healthy_integrations,
            "degraded_integrations": degraded_integrations,
            "events": total_events,
            "warning_events": warning_events,
        },
        "highlights": [
            {
                "label": "Registered integrations",
                "value": total_integrations,
            },
            {
                "label": "Healthy integrations",
                "value": healthy_integrations,
            },
            {
                "label": "Warning telemetry events",
                "value": warning_events,
            },
        ],
    }