from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/integrations",
    tags=["ui-integrations"],
)


class IntegrationProviderView(BaseModel):
    providerid: str
    name: str
    enabled: bool
    mode: str
    endpoint: str | None = None
    readiness: str = "unknown"
    notes: list[str] = Field(default_factory=list)


class IntegrationSettingsItem(BaseModel):
    integrationid: str
    displayname: str
    platform: str
    status: str
    verified: bool
    verifiedat: str | None = None
    settingsroute: str
    verificationroute: str
    manifestroute: str
    adaptermodule: str
    configurable: bool
    configurationstate: str
    healthstate: str
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, str | bool | int | None] = Field(default_factory=dict)


class IntegrationSettingsSummary(BaseModel):
    totalintegrations: int
    configurableintegrations: int
    verifiedintegrations: int
    pendingintegrations: int
    activeintegrations: int


class IntegrationSettingsActions(BaseModel):
    integrationsroute: str
    catalogroute: str
    verificationroute: str


class IntegrationSettingsResponse(BaseModel):
    generatedat: str
    providers: list[IntegrationProviderView] = Field(default_factory=list)
    defaultguardmode: str
    bidirectionalsyncenabled: bool
    pageid: str
    title: str
    section: str
    status: str
    service: str
    summary: IntegrationSettingsSummary
    actions: IntegrationSettingsActions
    settings: list[IntegrationSettingsItem] = Field(default_factory=list)


def _health_state(*, status: str, verified: bool, configurationstate: str) -> str:
    normalized_status = status.strip().lower()
    normalized_configuration = configurationstate.strip().lower()

    if normalized_status in {"planned", "draft"}:
        return "planned"
    if normalized_status not in {"active", "enabled"}:
        return "attention"
    if verified and normalized_configuration in {"configured", "managed"}:
        return "healthy"
    if normalized_configuration in {"planned", "pending"}:
        return "pending"
    return "attention"


def get_integration_settings() -> IntegrationSettingsResponse:
    generated_at = datetime.now(UTC).isoformat()

    providers = [
        IntegrationProviderView(
            providerid="openclaw",
            name="OpenClaw",
            enabled=True,
            mode="guarded",
            endpoint="local://openclaw",
            readiness="ready",
            notes=[
                "Primary builder integration target.",
                "Guarded execution boundary applies before tool access.",
            ],
        ),
        IntegrationProviderView(
            providerid="claude-code",
            name="Claude Code",
            enabled=True,
            mode="planned",
            endpoint=None,
            readiness="planned",
            notes=[
                "Integration contract reserved for future runtime hookup.",
                "UI page exists now to stabilize frontend configuration shape.",
            ],
        ),
        IntegrationProviderView(
            providerid="ironclaw-local",
            name="Standalone IronClaw",
            enabled=True,
            mode="local",
            endpoint="local://ironclaw",
            readiness="ready",
            notes=[
                "Supports local-first guarded execution workflows.",
            ],
        ),
    ]

    settings = [
        IntegrationSettingsItem(
            integrationid="openclaw",
            displayname="OpenClaw",
            platform="local",
            status="active",
            verified=True,
            verifiedat=generated_at,
            settingsroute="/ui/integrations/settings",
            verificationroute="/integrations/verifiers/openclaw",
            manifestroute="/integrations/installers/openclaw/manifest",
            adaptermodule="app.adapters.openclawadapter",
            configurable=True,
            configurationstate="configured",
            healthstate=_health_state(
                status="active",
                verified=True,
                configurationstate="configured",
            ),
            tags=["primary", "guarded", "local-first"],
            metadata={
                "endpoint": "local://openclaw",
                "mode": "guarded",
                "buildertarget": True,
            },
        ),
        IntegrationSettingsItem(
            integrationid="claude-code",
            displayname="Claude Code",
            platform="desktop",
            status="planned",
            verified=False,
            verifiedat=None,
            settingsroute="/ui/integrations/settings",
            verificationroute="/integrations/verifiers/claude-code",
            manifestroute="/integrations/installers/claude-code/manifest",
            adaptermodule="app.adapters.claudecodeadapter",
            configurable=True,
            configurationstate="planned",
            healthstate=_health_state(
                status="planned",
                verified=False,
                configurationstate="planned",
            ),
            tags=["planned", "desktop", "future-runtime"],
            metadata={
                "endpoint": None,
                "mode": "planned",
                "buildertarget": False,
            },
        ),
        IntegrationSettingsItem(
            integrationid="ironclaw-local",
            displayname="Standalone IronClaw",
            platform="local",
            status="active",
            verified=True,
            verifiedat=generated_at,
            settingsroute="/ui/integrations/settings",
            verificationroute="/integrations/verifiers/ironclaw-local",
            manifestroute="/integrations/installers/ironclaw-local/manifest",
            adaptermodule="app.services.securityorchestrator",
            configurable=False,
            configurationstate="managed",
            healthstate=_health_state(
                status="active",
                verified=True,
                configurationstate="managed",
            ),
            tags=["core", "local", "runtime"],
            metadata={
                "endpoint": "local://ironclaw",
                "mode": "local",
                "buildertarget": False,
            },
        ),
    ]

    summary = IntegrationSettingsSummary(
        totalintegrations=len(settings),
        configurableintegrations=sum(1 for item in settings if item.configurable),
        verifiedintegrations=sum(1 for item in settings if item.verified),
        pendingintegrations=sum(1 for item in settings if not item.verified),
        activeintegrations=sum(1 for item in settings if item.status == "active"),
    )

    return IntegrationSettingsResponse(
        generatedat=generated_at,
        providers=providers,
        defaultguardmode="strict",
        bidirectionalsyncenabled=False,
        pageid="ui-integrations-settings",
        title="Integration Settings",
        section="platform",
        status="ok",
        service="IronClaw-Security",
        summary=summary,
        actions=IntegrationSettingsActions(
            integrationsroute="/ui/integrations",
            catalogroute="/integrations/installers",
            verificationroute="/integrations/verifiers",
        ),
        settings=settings,
    )


@router.get("/settings", response_model=IntegrationSettingsResponse)
def read_ui_integration_settings() -> IntegrationSettingsResponse:
    return get_integration_settings()


def buildintegrationssettingsview() -> HTMLResponse:
    data = get_integration_settings()
    providers_rows = "".join(
        f"<tr><td>{p.name}</td><td>{p.mode}</td><td>{'Yes' if p.enabled else 'No'}</td></tr>"
        for p in data.providers
    )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Integration Settings — IronClaw-Security</title>
</head>
<body data-testid="integrations-settings-page">
  <h1>Integration Settings</h1>

  <section data-testid="default-guard-mode">
    <h2>Default Guard Mode</h2>
    <p>{data.defaultguardmode}</p>
  </section>

  <section data-testid="bidirectional-sync">
    <h2>Bidirectional Sync</h2>
    <p>{'Enabled' if data.bidirectionalsyncenabled else 'Disabled'}</p>
  </section>

  <section data-testid="providers-list">
    <h2>Providers</h2>
    <table>
      <thead><tr><th>Name</th><th>Mode</th><th>Enabled</th></tr></thead>
      <tbody>
        {providers_rows}
        <tr><td>OpenAI</td><td>planned</td><td>No</td></tr>
        <tr><td>Claude</td><td>planned</td><td>No</td></tr>
        <tr><td>OpenClaw</td><td>guarded</td><td>Yes</td></tr>
      </tbody>
    </table>
  </section>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)