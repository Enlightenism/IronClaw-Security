from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

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
                ),
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
                ),
            )

        return events


# ---------------------------------------------------------------------------
# IntegrationTelemetry — facade used by routes/integrations/telemetry.py
# Exposes .get(), .summary(), .metrics() over the event-based service above.
# ---------------------------------------------------------------------------


class IntegrationTelemetry:
    def __init__(self) -> None:
        self._service = IntegrationTelemetryService()

    def _build_payload(
        self,
        integration_id: str,
        environment: str = "production",
        window: str = "24h",
    ) -> dict[str, Any]:
        events = self._service.list_events(integrationid=integration_id)
        signals = [
            {
                "signal_id": ev.eventid,
                "category": ev.eventtype,
                "severity": "healthy" if ev.level == "info" else "warning",
                "status": "active",
                "title": ev.message,
                "detail": ev.message,
                "timestamp": ev.createdat,
                "metadata": {k: v for k, v in ev.metadata.items()},
            }
            for ev in events
        ]
        metrics: list[dict[str, Any]] = [
            {
                "metric": "event_count",
                "unit": "count",
                "points": [
                    {
                        "timestamp": datetime.now(UTC).isoformat(),
                        "value": float(len(events)),
                        "label": "total",
                    }
                ],
                "metadata": {"integration_id": integration_id},
            }
        ]
        return {
            "environment": environment,
            "window": window,
            "updated_at": datetime.now(UTC).isoformat(),
            "signals": signals,
            "metrics": metrics,
        }

    def get(
        self,
        integration_id: str,
        environment: str = "production",
        window: str = "24h",
    ) -> dict[str, Any]:
        return self._build_payload(integration_id, environment, window)

    def summary(
        self,
        integration_id: str,
        environment: str = "production",
        window: str = "24h",
    ) -> dict[str, Any]:
        return self._build_payload(integration_id, environment, window)

    def metrics(
        self,
        integration_id: str,
        environment: str = "production",
        window: str = "24h",
    ) -> dict[str, Any]:
        return self._build_payload(integration_id, environment, window)


_telemetry_service = IntegrationTelemetryService()


def get_integration_telemetry_service() -> IntegrationTelemetryService:
    return _telemetry_service


__all__ = [
    "IntegrationTelemetry",
    "IntegrationTelemetryEvent",
    "IntegrationTelemetryService",
    "get_integration_telemetry_service",
]
