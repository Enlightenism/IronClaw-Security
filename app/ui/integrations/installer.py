from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_installer import (
    install_integration,
    summarize_install_result,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
    initialize_integration_registry,
    list_integrations,
)


@dataclass(slots=True)
class IntegrationInstallerAction:
    integration_id: str
    dry_run: bool = False
    requested_by: str | None = "ui"
    install_target: str | None = None
    extra_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "dry_run": self.dry_run,
            "requested_by": self.requested_by,
            "install_target": self.install_target,
            "extra_metadata": dict(self.extra_metadata),
        }


@dataclass(slots=True)
class IntegrationInstallerCard:
    integration_id: str
    name: str
    slug: str
    platform: str
    status: str
    version: str
    command_name: str | None
    install_target: str | None
    description: str
    one_command_ready: bool
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "name": self.name,
            "slug": self.slug,
            "platform": self.platform,
            "status": self.status,
            "version": self.version,
            "command_name": self.command_name,
            "install_target": self.install_target,
            "description": self.description,
            "one_command_ready": self.one_command_ready,
            "capabilities": list(self.capabilities),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationInstallerView:
    title: str
    total: int
    ready_count: int
    items: list[IntegrationInstallerCard] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "ready_count": self.ready_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_installer_card(
    integration_id: str,
    *,
    registry: IntegrationRegistry,
) -> IntegrationInstallerCard:
    record = get_integration(registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    enabled_capabilities = [
        capability.name
        for capability in record.capabilities
        if capability.enabled
    ]

    return IntegrationInstallerCard(
        integration_id=record.integration_id,
        name=record.name,
        slug=record.slug,
        platform=record.platform,
        status=record.status,
        version=record.version,
        command_name=record.command_name,
        install_target=record.install_target,
        description=record.description,
        one_command_ready=bool(record.command_name),
        capabilities=enabled_capabilities,
        metadata=dict(record.metadata),
    )


def build_integration_installer_view(
    *,
    registry: IntegrationRegistry | None = None,
) -> IntegrationInstallerView:
    active_registry = registry or initialize_integration_registry()
    records = list_integrations(active_registry)

    cards = [
        build_integration_installer_card(
            record.integration_id,
            registry=active_registry,
        )
        for record in records
    ]

    ready_count = sum(1 for card in cards if card.one_command_ready)

    return IntegrationInstallerView(
        title="Integration Installer",
        total=len(cards),
        ready_count=ready_count,
        items=cards,
        metadata={
            "created_at": active_registry.created_at,
            "updated_at": active_registry.updated_at,
        },
    )


def execute_integration_installer_action(
    action: IntegrationInstallerAction,
    *,
    registry: IntegrationRegistry | None = None,
) -> dict[str, Any]:
    active_registry = registry or initialize_integration_registry()

    result = install_integration(
        active_registry,
        action.integration_id,
        dry_run=action.dry_run,
        requested_by=action.requested_by,
        install_target=action.install_target,
        extra_metadata=dict(action.extra_metadata),
    )
    summary = summarize_install_result(result)

    return {
        "action": action.to_dict(),
        "result": dict(summary),
    }