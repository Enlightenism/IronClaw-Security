from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from app.services.integrationinstaller import get_integration_installer
from app.services.integrationregistry import get_integration_registry
from app.services.integrationverifier import get_integration_verifier


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def build_ui_integrations_page() -> dict[str, object]:
    registry = get_integration_registry()
    installer = get_integration_installer()
    verifier = get_integration_verifier()

    integrations = []
    ready_count = 0
    installed_count = 0

    for record in registry.list_integrations():
        installer_preview = installer.install_integration(
            record.integrationid,
            requestedby="ui-preview",
        )
        verifier_preview = verifier.verify_integration(
            record.integrationid,
            strict=False,
            requestedby="ui-preview",
        )

        integration_payload = {
            "integrationid": record.integrationid,
            "platform": record.platform,
            "displayname": record.displayname,
            "status": record.status,
            "installed": record.installedat is not None,
            "installedat": record.installedat,
            "verified": record.verified,
            "verifiedat": record.verifiedat,
            "settingsroute": record.settingsroute,
            "manifestroute": record.manifestroute,
            "verificationroute": record.verificationroute,
            "adaptermodule": record.adaptermodule,
            "capabilities": [asdict(capability) for capability in record.capabilities],
            "installerpreview": (
                {
                    "installed": installer_preview.installed,
                    "status": installer_preview.status,
                    "summary": installer_preview.summary,
                    "steps": [asdict(step) for step in installer_preview.steps],
                }
                if installer_preview is not None
                else None
            ),
            "verifierpreview": (
                {
                    "verified": verifier_preview.verified,
                    "status": verifier_preview.status,
                    "strict": verifier_preview.strict,
                    "summary": verifier_preview.summary,
                    "checks": [asdict(check) for check in verifier_preview.checks],
                    "missingcapabilities": list(
                        verifier_preview.missingcapabilities
                    ),
                }
                if verifier_preview is not None
                else None
            ),
            "health": "ready" if record.verified else "degraded",
        }
        integrations.append(integration_payload)

        if integration_payload["installed"]:
            installed_count += 1
        if integration_payload["health"] == "ready":
            ready_count += 1

    return {
        "pageid": "ui-integrations",
        "title": "Integrations",
        "section": "platform",
        "status": "ok",
        "service": "IronClaw-Security",
        "generatedat": _utc_now(),
        "summary": {
            "totalintegrations": len(integrations),
            "installedintegrations": installed_count,
            "readyintegrations": ready_count,
            "degradedintegrations": len(integrations) - ready_count,
        },
        "actions": {
            "catalogroute": "/integrations/installers",
            "verificationroute": "/integrations/verifiers",
            "settingsroute": "/ui/integrations/settings",
        },
        "integrations": integrations,
    }


def get_ui_integrations_page() -> dict[str, object]:
    return build_ui_integrations_page()