from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
    summarize_integration_registry,
)


@dataclass(slots=True)
class IntegrationProfileSection:
    key: str
    title: str
    items: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "items": dict(self.items),
        }


@dataclass(slots=True)
class IntegrationProfileView:
    title: str
    integration_id: str
    slug: str
    name: str
    platform: str
    integration_type: str
    status: str
    version: str
    command_name: str | None
    install_target: str | None
    sections: list[IntegrationProfileSection] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "integration_type": self.integration_type,
            "status": self.status,
            "version": self.version,
            "command_name": self.command_name,
            "install_target": self.install_target,
            "sections": [section.to_dict() for section in self.sections],
            "summary": dict(self.summary),
            "metadata": dict(self.metadata),
        }


def build_integration_profile_view(
    *,
    registry: IntegrationRegistry,
    integration_id: str,
    requested_by: str = "ui-profile",
) -> IntegrationProfileView:
    record = get_integration(registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    record_metadata = dict(getattr(record, "metadata", {}) or {})
    integration_type = getattr(record, "integration_type", "unknown")
    command_name = getattr(record, "command_name", None)
    install_target = getattr(record, "install_target", None)
    endpoint = getattr(record, "endpoint", None)
    base_url = getattr(record, "base_url", None)

    overview = IntegrationProfileSection(
        key="overview",
        title="Overview",
        items={
            "integration_id": record.integration_id,
            "slug": record.slug,
            "name": record.name,
            "platform": record.platform,
            "integration_type": integration_type,
            "status": record.status,
            "version": record.version,
        },
    )

    execution = IntegrationProfileSection(
        key="execution",
        title="Execution",
        items={
            "command_name": command_name,
            "install_target": install_target,
            "endpoint": endpoint,
            "base_url": base_url,
        },
    )

    capabilities = IntegrationProfileSection(
        key="capabilities",
        title="Capabilities",
        items={
            "has_command": bool(command_name),
            "has_install_target": bool(install_target),
            "has_endpoint": bool(endpoint or base_url),
            "metadata_keys": sorted(record_metadata.keys()),
        },
    )

    metadata_section = IntegrationProfileSection(
        key="metadata",
        title="Metadata",
        items={
            "requested_by": requested_by,
            "record_metadata": record_metadata,
        },
    )

    return IntegrationProfileView(
        title=f"{record.name} Profile",
        integration_id=record.integration_id,
        slug=record.slug,
        name=record.name,
        platform=record.platform,
        integration_type=integration_type,
        status=record.status,
        version=record.version,
        command_name=command_name,
        install_target=install_target,
        sections=[overview, execution, capabilities, metadata_section],
        summary=summarize_integration_registry(registry),
        metadata={
            "requested_by": requested_by,
        },
    )
