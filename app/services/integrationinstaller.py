from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.services.integrationregistry import IntegrationRecord, get_integration_registry


@dataclass(slots=True)
class IntegrationInstallStep:
    stepid: str
    label: str
    completed: bool
    detail: str


@dataclass(slots=True)
class IntegrationInstallResult:
    integrationid: str
    platform: str
    status: str
    installed: bool
    installedat: str | None
    requestedby: str
    steps: list[IntegrationInstallStep] = field(default_factory=list)
    summary: str = ""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class IntegrationInstaller:
    def install_integration(
        self,
        integrationid: str,
        *,
        requestedby: str = "system",
    ) -> IntegrationInstallResult | None:
        normalizedintegrationid = integrationid.strip().lower()
        normalizedrequestedby = requestedby.strip() or "system"

        if not normalizedintegrationid:
            return None

        registry = get_integration_registry()
        record = registry.get_integration(normalizedintegrationid)
        if record is None:
            return None

        steps = self._build_steps(record)
        installed = all(step.completed for step in steps)

        if installed:
            installedrecord = registry.install_integration(record.integrationid)
            if installedrecord is None:
                return None

            if installedrecord.status == "available":
                registry.update_status(installedrecord.integrationid, "configured")

            finalrecord = registry.get_integration(record.integrationid)
            if finalrecord is None:
                return None

            return IntegrationInstallResult(
                integrationid=finalrecord.integrationid,
                platform=finalrecord.platform,
                status=finalrecord.status,
                installed=True,
                installedat=finalrecord.installedat,
                requestedby=normalizedrequestedby,
                steps=steps,
                summary=(
                    f"Integration {finalrecord.integrationid} install workflow completed."
                ),
            )

        return IntegrationInstallResult(
            integrationid=record.integrationid,
            platform=record.platform,
            status="degraded",
            installed=False,
            installedat=record.installedat,
            requestedby=normalizedrequestedby,
            steps=steps,
            summary=f"Integration {record.integrationid} install workflow failed.",
        )

    def _build_steps(self, record: IntegrationRecord) -> list[IntegrationInstallStep]:
        installedat = record.installedat or _utc_now()
        return [
            IntegrationInstallStep(
                stepid="registry-check",
                label="Registry entry available",
                completed=bool(record.integrationid.strip()),
                detail=record.integrationid,
            ),
            IntegrationInstallStep(
                stepid="adapter-module",
                label="Adapter module declared",
                completed=bool(record.adaptermodule.strip()),
                detail=record.adaptermodule,
            ),
            IntegrationInstallStep(
                stepid="settings-route",
                label="Settings route mapped",
                completed=record.settingsroute.startswith("/"),
                detail=record.settingsroute,
            ),
            IntegrationInstallStep(
                stepid="manifest-route",
                label="Manifest route mapped",
                completed=record.manifestroute.startswith("/"),
                detail=record.manifestroute,
            ),
            IntegrationInstallStep(
                stepid="install-stamp",
                label="Install timestamp prepared",
                completed=True,
                detail=installedat,
            ),
        ]


_installer = IntegrationInstaller()


def get_integration_installer() -> IntegrationInstaller:
    return _installer


def install_integration(
    integrationid: str,
    *,
    requestedby: str = "system",
) -> IntegrationInstallResult | None:
    return _installer.install_integration(
        integrationid,
        requestedby=requestedby,
    )