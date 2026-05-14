from __future__ import annotations

from datetime import UTC, datetime

from app.services.integrationregistry import get_integration_registry


def _generated_at() -> str:
    return datetime.now(UTC).isoformat()


def build_ui_integration_settings_page() -> dict[str, object]:
    registry = get_integration_registry()
    records = registry.list_integrations()

    settings: list[dict[str, object]] = []
    configurable_count = 0
    verified_count = 0

    for record in records:
        configurable = bool(record.settingsroute)
        verified = bool(record.verifiedat)

        if configurable:
            configurable_count += 1
        if verified:
            verified_count += 1

        settings.append(
            {
                "integrationid": record.integrationid,
                "displayname": record.displayname,
                "platform": record.platform,
                "status": record.status,
                "verified": verified,
                "verifiedat": record.verifiedat,
                "settingsroute": record.settingsroute,
                "verificationroute": record.verificationroute,
                "manifestroute": record.manifestroute,
                "adaptermodule": record.adaptermodule,
                "configurable": configurable,
                "configurationstate": ("configured" if verified else "pending" if configurable else "unavailable"),
                "tags": list(record.tags),
                "metadata": dict(record.metadata),
            },
        )

    return {
        "pageid": "ui-integrations-settings",
        "title": "Integration Settings",
        "section": "platform",
        "status": "ok",
        "service": "IronClaw-Security",
        "generatedat": _generated_at(),
        "summary": {
            "totalintegrations": len(settings),
            "configurableintegrations": configurable_count,
            "verifiedintegrations": verified_count,
            "pendingintegrations": len(settings) - verified_count,
        },
        "actions": {
            "integrationsroute": "/ui/integrations",
            "catalogroute": "/integrations/installers",
            "verificationroute": "/integrations/verifiers",
        },
        "settings": settings,
    }


def get_ui_integration_settings_page() -> dict[str, object]:
    return build_ui_integration_settings_page()
