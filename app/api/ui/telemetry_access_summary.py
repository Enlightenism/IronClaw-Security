from __future__ import annotations

from fastapi import APIRouter

from app.services.integrationregistry import get_integration_registry
from app.services.integrationtelemetry import get_integration_telemetry_service


router = APIRouter(
    prefix="/ui/telemetry-access-summary",
    tags=["ui-telemetry-access-summary"],
)


@router.get("")
def read_telemetry_access_summary() -> dict[str, object]:
    registry = get_integration_registry()
    telemetry_service = get_integration_telemetry_service()

    integrations = registry.list_integrations()
    events = telemetry_service.list_events()

    healthy_statuses = {"available", "configured", "ready"}

    integration_summaries = []
    for integration in integrations:
        integration_events = [
            event for event in events if event.integrationid == integration.integrationid
        ]
        integration_summaries.append(
            {
                "integration_id": integration.integrationid,
                "platform": integration.platform,
                "display_name": integration.displayname,
                "status": integration.status,
                "status_tone": (
                    "healthy" if integration.status in healthy_statuses else "warning"
                ),
                "event_count": len(integration_events),
                "latest_event_at": (
                    max((event.createdat for event in integration_events), default=None)
                ),
            }
        )

    info_events = sum(1 for event in events if event.level == "info")
    warning_events = sum(1 for event in events if event.level == "warning")

    return {
        "total_integrations": len(integrations),
        "healthy_integrations": sum(
            1 for integration in integrations if integration.status in healthy_statuses
        ),
        "warning_integrations": sum(
            1 for integration in integrations if integration.status not in healthy_statuses
        ),
        "total_events": len(events),
        "info_events": info_events,
        "warning_events": warning_events,
        "items": integration_summaries,
    }