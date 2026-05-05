from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.services.integrationregistry import get_integration_registry


@dataclass(slots=True)
class IntegrationTelemetryEvent:
    eventid: str
    integrationid: str
    platform: str
    eventtype: str
    level: str
    message: str
    createdat: str
    metadata: dict[str, str] = field(default_factory=dict)


class IntegrationTelemetryService:
    def list_events(self, integrationid: str | None = None) -> list[IntegrationTelemetryEvent]:
        registry = get_integration_registry()
        records = registry.list_integrations()

        events: list[IntegrationTelemetryEvent] = []
        for record in records:
            if integrationid and record.integrationid != integrationid:
                continue

            events.append(
                IntegrationTelemetryEvent(
                    eventid=f"{record.integrationid}-status",
                    integrationid=record.integrationid,
                    platform=record.platform,
                    eventtype="integration_status",
                    level="info" if record.status in {"available", "configured", "ready"} else "warning",
                    message=f"{record.displayname} status is {record.status}.",
                    createdat=datetime.now(UTC).isoformat(),
                    metadata={
                        "status": record.status,
                        "settingsroute": record.settingsroute,
                    },
                )
            )

            events.append(
                IntegrationTelemetryEvent(
                    eventid=f"{record.integrationid}-verification",
                    integrationid=record.integrationid,
                    platform=record.platform,
                    eventtype="integration_verification_target",
                    level="info",
                    message=f"{record.displayname} verification route is ready.",
                    createdat=datetime.now(UTC).isoformat(),
                    metadata={
                        "verificationroute": record.verificationroute,
                        "manifestroute": record.manifestroute,
                    },
                )
            )

        return events


_telemetry_service = IntegrationTelemetryService()


def get_integration_telemetry_service() -> IntegrationTelemetryService:
    return _telemetry_service