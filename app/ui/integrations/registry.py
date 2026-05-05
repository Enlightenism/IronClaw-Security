from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
    summarize_integration_registry,
)


@dataclass(slots=True)
class IntegrationRegistryItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    integration_type: str
    status: str
    version: str
    command_name: str | None
    install_target: str | None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "integration_type": self.integration_type,
            "status": self.status,
            "version": self.version,
            "command_name": self.command_name,
            "install_target": self.install_target,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationRegistryView:
    title: str
    total: int
    summary: dict[str, Any] = field(default_factory=dict)
    items: list[IntegrationRegistryItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "summary": dict(self.summary),
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_registry_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-registry",
) -> IntegrationRegistryView:
    records = list_integrations(registry)

    items: list[IntegrationRegistryItem] = []
    for record in records:
        items.append(
            IntegrationRegistryItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                integration_type=getattr(record, "integration_type", "unknown"),
                status=record.status,
                version=record.version,
                command_name=getattr(record, "command_name", None),
                install_target=getattr(record, "install_target", None),
                metadata={
                    "requested_by": requested_by,
                },
            )
        )

    items.sort(key=lambda item: (item.platform, item.slug, item.integration_id))

    return IntegrationRegistryView(
        title="Integration Registry",
        total=len(items),
        summary=summarize_integration_registry(registry),
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )