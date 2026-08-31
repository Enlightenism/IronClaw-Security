from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.core.install_key_formats import InstallKeyFormatRegistry, get_install_key_format_spec

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
    installkeyprogram: str | None = None
    installkeyfamily: str | None = None
    installkeyprefix: str | None = None
    installkeyaliases: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    installkeyprogram: str | None = None
    installkeyfamily: str | None = None
    installkeyprefix: str | None = None
    installkeyaliases: list[str] = Field(default_factory=list)
    installertype: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


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


def _build_provider_metadata(spec: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "install_key_program": spec.program,
        "install_key_family": spec.family,
        "install_key_prefix": spec.prefix,
        "display_name": spec.display_name,
        "platform_aliases": list(spec.platform_aliases),
        "aliases": list(spec.aliases),
    }
    if spec.program == "security_guardian":
        metadata["shared_package_semantics"] = "shared package; not a standalone runtime"
    return metadata


def _filter_legacy_provider_names(items: list[IntegrationProviderView]) -> list[IntegrationProviderView]:
    return [item for item in items if item.name != "Standalone IronClaw"]


def _build_platform_config_panels() -> tuple[list[IntegrationProviderView], list[IntegrationSettingsItem]]:
    providers: list[IntegrationProviderView] = []
    settings: list[IntegrationSettingsItem] = []

    for program in InstallKeyFormatRegistry.list_programs():
        spec = get_install_key_format_spec(program)
        provider_id = spec.program
        endpoint = f"local://{program}"
        config_state = "configured" if program in {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes"} else "managed"
        status = "active"
        verified = True
        health = _health_state(
            status=status,
            verified=verified,
            configurationstate=config_state,
        )
        metadata = _build_provider_metadata(spec)
        notes = [
            f"Uses the {spec.display_name} install-key family.",
            "Shared key-family semantics are preserved across the matching platform aliases.",
        ]
        if spec.program == "security_guardian":
            notes.append("Security Guardian is a shared package for the supported runtime family set, not a standalone runtime label.")

        providers.append(
            IntegrationProviderView(
                providerid=provider_id,
                name=spec.display_name,
                enabled=True,
                mode="guarded",
                endpoint=endpoint,
                readiness="ready",
                installkeyprogram=spec.program,
                installkeyfamily=spec.family,
                installkeyprefix=spec.prefix,
                installkeyaliases=list(spec.platform_aliases),
                notes=notes,
                metadata=metadata,
            ),
        )

        settings.append(
            IntegrationSettingsItem(
                integrationid=provider_id,
                displayname=spec.display_name,
                platform=spec.program,
                status=status,
                verified=verified,
                verifiedat=None,
                settingsroute=f"/ui/integrations/settings/{provider_id}",
                verificationroute=f"/integrations/verifiers/{provider_id}",
                manifestroute=f"/integrations/installers/{provider_id}/manifest",
                adaptermodule=f"app.adapters.{provider_id}",
                configurable=True,
                configurationstate=config_state,
                healthstate=health,
                installkeyprogram=spec.program,
                installkeyfamily=spec.family,
                installkeyprefix=spec.prefix,
                installkeyaliases=list(spec.platform_aliases),
                installertype="install-key",
                tags=[
                    spec.program,
                    "install-key",
                    "platform-config",
                    *(["shared-package"] if spec.program == "security_guardian" else []),
                ],
                metadata={
                    **metadata,
                    "endpoint": endpoint,
                    "mode": "guarded",
                    "installer_path": endpoint,
                },
            ),
        )

    return _filter_legacy_provider_names(providers), settings


def get_integration_settings() -> IntegrationSettingsResponse:
    generated_at = datetime.now(UTC).isoformat()
    providers, settings = _build_platform_config_panels()

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
    providers_rows = "".join(f"<tr><td>{p.name}</td><td>{p.mode}</td><td>{'Yes' if p.enabled else 'No'}</td></tr>" for p in data.providers)
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
    <p>{"Enabled" if data.bidirectionalsyncenabled else "Disabled"}</p>
  </section>

  <section data-testid="providers-list">
    <h2>Providers</h2>
    <table>
      <thead><tr><th>Name</th><th>Mode</th><th>Enabled</th></tr></thead>
      <tbody>
        {providers_rows}
      </tbody>
    </table>
  </section>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)
