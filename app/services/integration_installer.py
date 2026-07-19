from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.services.integration_registry import (
    IntegrationRecord,
    IntegrationRegistry,
    get_integration,
    get_integration_registry,
    update_integration_status,
)

InstallState = Literal["pending", "installed", "skipped", "failed"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class InstallStepResult:
    name: str
    state: InstallState
    message: str
    command: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "message": self.message,
            "command": self.command,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationInstallResult:
    integration_id: str
    slug: str
    status_before: str
    status_after: str
    installed: bool
    command_name: str | None
    install_target: str | None
    started_at: str
    completed_at: str
    steps: list[InstallStepResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "status_before": self.status_before,
            "status_after": self.status_after,
            "installed": self.installed,
            "command_name": self.command_name,
            "install_target": self.install_target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "steps": [step.to_dict() for step in self.steps],
            "metadata": dict(self.metadata),
        }


def install_integration(
    registry: IntegrationRegistry,
    integration_id: str,
    *,
    dry_run: bool = False,
    requested_by: str | None = None,
    install_target: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> IntegrationInstallResult:
    record = get_integration(registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    started_at = _utc_now()
    status_before = record.status
    effective_target = install_target or record.install_target

    steps: list[InstallStepResult] = [
        InstallStepResult(
            name="resolve-integration",
            state="installed",
            message=f"Resolved integration '{record.slug}'.",
            metadata={"platform": record.platform},
        ),
        InstallStepResult(
            name="validate-command",
            state="installed" if record.command_name else "skipped",
            message=("Install command available." if record.command_name else "No install command registered yet."),
            command=record.command_name,
        ),
        InstallStepResult(
            name="prepare-target",
            state="installed" if effective_target else "skipped",
            message=(f"Prepared install target '{effective_target}'." if effective_target else "No install target declared."),
            metadata={"install_target": effective_target},
        ),
    ]

    metadata = dict(extra_metadata or {})
    if requested_by:
        metadata["requested_by"] = requested_by
    if dry_run:
        metadata["dry_run"] = True

    status_after = status_before
    installed = False

    if dry_run:
        steps.append(
            InstallStepResult(
                name="apply-install",
                state="skipped",
                message="Dry run only; no changes applied.",
            ),
        )
    else:
        update_integration_status(registry, integration_id, "active")
        status_after = "active"
        installed = True
        steps.append(
            InstallStepResult(
                name="apply-install",
                state="installed",
                message=f"Integration '{record.slug}' marked active.",
            ),
        )

    completed_at = _utc_now()
    refreshed_record = get_integration(registry, integration_id) or record

    return IntegrationInstallResult(
        integration_id=refreshed_record.integration_id,
        slug=refreshed_record.slug,
        status_before=status_before,
        status_after=status_after,
        installed=installed,
        command_name=refreshed_record.command_name,
        install_target=effective_target,
        started_at=started_at,
        completed_at=completed_at,
        steps=steps,
        metadata=metadata,
    )


def build_install_plan(record: IntegrationRecord) -> list[dict[str, Any]]:
    return [
        {
            "step": "resolve-integration",
            "description": f"Resolve integration metadata for '{record.slug}'.",
        },
        {
            "step": "validate-command",
            "description": "Confirm one-command installer entrypoint exists.",
            "command": record.command_name,
        },
        {
            "step": "prepare-target",
            "description": "Prepare target platform for local IronClaw attachment.",
            "install_target": record.install_target,
        },
        {
            "step": "apply-install",
            "description": "Activate the integration and expose protected runtime hooks.",
        },
    ]


def summarize_install_result(result: IntegrationInstallResult) -> dict[str, Any]:
    return {
        "integration_id": result.integration_id,
        "slug": result.slug,
        "installed": result.installed,
        "status_before": result.status_before,
        "status_after": result.status_after,
        "step_count": len(result.steps),
        "completed_at": result.completed_at,
        "command_name": result.command_name,
        "install_target": result.install_target,
    }


def get_integration_installer() -> Any:
    registry = get_integration_registry()

    class _IntegrationInstaller:
        def install_integration(
            self,
            integration_id: str,
            *,
            dry_run: bool = False,
            requested_by: str | None = None,
            install_target: str | None = None,
            extra_metadata: dict[str, Any] | None = None,
        ) -> IntegrationInstallResult:
            return install_integration(
                registry,
                integration_id,
                dry_run=dry_run,
                requested_by=requested_by,
                install_target=install_target,
                extra_metadata=extra_metadata,
            )

    return _IntegrationInstaller()
