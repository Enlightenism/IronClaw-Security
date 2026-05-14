from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.integrations import (
    IntegrationCapability,
    IntegrationRecord,
    IntegrationStatus,
)
from app.services.integrationregistry import IntegrationRegistryService
from app.services.integrationtelemetry import IntegrationTelemetryService


class IntegrationsOverviewIntegrationItem(BaseModel):
    """Compact integration row for the UI overview.

    This intentionally mirrors the shapes already exposed in the public
    IntegrationRecordResponse / IntegrationSettingsItem schemas but keeps
    only the fields needed for a single overview page so we do not
    accidentally leak internal metadata.
    """

    integration_id: str = Field(..., alias="integrationid")
    slug: str
    display_name: str = Field(..., alias="displayname")
    platform: str
    status: str
    configurable: bool = False
    verified: bool = False
    configuration_state: str | None = Field(default=None, alias="configurationstate")
    settings_route: str | None = Field(default=None, alias="settingsroute")
    manifest_route: str | None = Field(default=None, alias="manifestroute")
    tags: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    risk_score: int | None = Field(
        default=None,
        description="Optional normalized risk or posture score (0–100) from telemetry.",
    )

    class Config:
        allow_population_by_field_name = True


class IntegrationsOverviewSummary(BaseModel):
    """High-level summary metrics for the integrations overview page.

    This is a thin wrapper around the IntegrationRegistrySummaryResponse
    and the IntegrationSettingsSummary shapes already exposed via the API.
    """

    total_integrations: int = Field(..., alias="totalintegrations")
    configurable_integrations: int = Field(..., alias="configurableintegrations")
    verified_integrations: int = Field(..., alias="verifiedintegrations")
    pending_integrations: int = Field(..., alias="pendingintegrations")
    platforms: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)

    class Config:
        allow_population_by_field_name = True


class IntegrationsOverviewPage(BaseModel):
    """View model for the /ui/integrations overview page.

    This is what the ui router will serialize for the UI manifest and
    for any dedicated integrations overview endpoint.
    """

    generated_at: datetime = Field(..., alias="generatedat")
    summary: IntegrationsOverviewSummary
    integrations: list[IntegrationsOverviewIntegrationItem]

    class Config:
        allow_population_by_field_name = True


def _map_integration_record_to_item(
    record: IntegrationRecord,
    risk_score: int | None = None,
) -> IntegrationsOverviewIntegrationItem:
    """Map a core IntegrationRecord domain object into the compact
    overview item model used by the UI layer.

    We intentionally normalize enums to their value strings so the UI
    doesn’t need to know about Python enum types.
    """
    status_value = record.status.value if isinstance(record.status, IntegrationStatus) else str(record.status)

    capabilities: list[str] = []
    if getattr(record, "capabilities", None):
        for cap in record.capabilities:
            if isinstance(cap, IntegrationCapability):
                capabilities.append(cap.value)
            else:
                capabilities.append(str(cap))

    return IntegrationsOverviewIntegrationItem(
        integrationid=record.integration_id,
        slug=record.slug,
        displayname=record.display_name,
        platform=record.platform,
        status=status_value,
        configurable=getattr(record, "configurable", False),
        verified=getattr(record, "verified", False),
        configurationstate=getattr(record, "configuration_state", None),
        settingsroute=getattr(record, "settings_route", None),
        manifestroute=getattr(record, "manifest_route", None),
        tags=list(getattr(record, "tags", []) or []),
        capabilities=capabilities,
        risk_score=risk_score,
    )


def get_page() -> IntegrationsOverviewPage:
    """Build the integrations overview UI page model.

    This function is intentionally side-effect free and uses the existing
    integration registry + telemetry services to assemble a consistent view
    for operators. It is designed to be safe to call from tests and from
    the ui router bootstrap.
    """
    registry = IntegrationRegistryService()
    telemetry = IntegrationTelemetryService()

    # Fetch the full registry plus summary so we can hydrate both the
    # top-level summary block and the integration list.
    registry_snapshot = registry.get_registry_snapshot()
    # registry_snapshot is expected to expose:
    #   - items: List[IntegrationRecord]
    #   - summary: object with totalintegrations, configurableintegrations,
    #              verifiedintegrations, pendingintegrations, platforms, capabilities
    # which mirrors IntegrationRegistrySummaryResponse / IntegrationSettingsSummary
    # as declared in the OpenAPI components.[file:2]

    # Build summary view, tolerating missing attributes to avoid brittle failures.
    summary = IntegrationsOverviewSummary(
        totalintegrations=getattr(
            registry_snapshot.summary,
            "totalintegrations",
            len(registry_snapshot.items),
        ),
        configurableintegrations=getattr(
            registry_snapshot.summary,
            "configurableintegrations",
            0,
        ),
        verifiedintegrations=getattr(
            registry_snapshot.summary,
            "verifiedintegrations",
            0,
        ),
        pendingintegrations=getattr(
            registry_snapshot.summary,
            "pendingintegrations",
            0,
        ),
        platforms=list(getattr(registry_snapshot.summary, "platforms", []) or []),
        capabilities=list(getattr(registry_snapshot.summary, "capabilities", []) or []),
    )

    # Optionally hydrate per-integration risk or posture scores from telemetry.
    risk_index = telemetry.get_integration_risk_index()
    # risk_index is expected to be a mapping of integration_id -> int score (0–100),
    # but we treat it as a generic mapping to keep the page robust.

    items: list[IntegrationsOverviewIntegrationItem] = []
    for record in registry_snapshot.items:
        risk_score = None
        if risk_index and getattr(record, "integration_id", None):
            risk_score = risk_index.get(record.integration_id)
        items.append(_map_integration_record_to_item(record, risk_score=risk_score))

    return IntegrationsOverviewPage(
        generatedat=datetime.utcnow(),
        summary=summary,
        integrations=items,
    )
