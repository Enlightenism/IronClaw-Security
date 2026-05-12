from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter

from app.services.integrationregistry import get_integration_registry
from app.services.integrationtelemetry import get_integration_telemetry_service

router = APIRouter(prefix="/ui/runtime-status", tags=["ui-runtime-status"])


@router.get("")
def read_runtime_status() -> dict[str, object]:
    registry = get_integration_registry()
    telemetry_service = get_integration_telemetry_service()

    integrations = registry.list_integrations()
    events = telemetry_service.list_events()

    healthy_statuses = {"available", "configured", "ready"}
    degraded_statuses = {"degraded", "disabled"}

    latest_event_at = max((event.createdat for event in events), default=None)

    return {
        "environment": "local",
        "service": "ironclaw-security",
        "status": (
            "healthy"
            if all(item.status in healthy_statuses for item in integrations)
            else "degraded"
        ),
        "generated_at": datetime.now(UTC).isoformat(),
        "latest_event_at": latest_event_at,
        "integration_summary": {
            "total": len(integrations),
            "healthy": sum(1 for item in integrations if item.status in healthy_statuses),
            "degraded": sum(1 for item in integrations if item.status in degraded_statuses),
            "other": sum(
                1
                for item in integrations
                if item.status not in healthy_statuses
                and item.status not in degraded_statuses
            ),
        },
        "telemetry_summary": {
            "total_events": len(events),
            "info_events": sum(1 for event in events if event.level == "info"),
            "warning_events": sum(1 for event in events if event.level == "warning"),
        },
        "items": [
            {
                "integration_id": item.integrationid,
                "platform": item.platform,
                "display_name": item.displayname,
                "status": item.status,
                "status_tone": (
                    "healthy" if item.status in healthy_statuses else "warning"
                ),
                "settings_route": item.settingsroute,
                "verification_route": item.verificationroute,
            }
            for item in integrations
        ],
    }