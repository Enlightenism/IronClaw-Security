from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
    summarize_integration_registry,
)


@dataclass(slots=True)
class IntegrationCatalogFilter:
    status: str | None = None
    platform: str | None = None
    capability: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "platform": self.platform,
            "capability": self.capability,
        }


@dataclass(slots=True)
class IntegrationCatalogItem:
    integration_id: str
    name: str
    slug: str
    platform: str
    integration_type: str
    status: str
    version: str
    command_name: str | None = None
    description: str = ""
    install_target: str | None = None
    enabled_capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "name": self.name,
            "slug": self.slug,
            "platform": self.platform,
            "integration_type": self.integration_type,
            "status": self.status,
            "version": self.version,
            "command_name": self.command_name,
            "description": self.description,
            "install_target": self.install_target,
            "enabled_capabilities": list(self.enabled_capabilities),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationCatalogView:
    title: str
    total: int
    filters: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    items: list[IntegrationCatalogItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "filters": dict(self.filters),
            "summary": dict(self.summary),
            "items": [item.to_dict() for item in self.items],
        }


def _normalize_text(value: str | None) -> str | None:
    normalized = (value or "").strip()
    return normalized or None


def build_integration_catalog_view(
    registry: IntegrationRegistry,
    *,
    catalog_filter: IntegrationCatalogFilter | None = None,
) -> IntegrationCatalogView:
    active_filter = catalog_filter or IntegrationCatalogFilter()

    items = list_integrations(
        registry,
        status=_normalize_text(active_filter.status),
        platform=_normalize_text(active_filter.platform),
        capability=_normalize_text(active_filter.capability),
    )

    catalog_items = [
        IntegrationCatalogItem(
            integration_id=item.integration_id,
            name=item.name,
            slug=item.slug,
            platform=item.platform,
            integration_type=item.integration_type,
            status=item.status,
            version=item.version,
            command_name=item.command_name,
            description=item.description,
            install_target=item.install_target,
            enabled_capabilities=[capability.name for capability in item.capabilities if capability.enabled],
            metadata=dict(item.metadata),
        )
        for item in items
    ]

    return IntegrationCatalogView(
        title="Integrations Catalog",
        total=len(catalog_items),
        filters=active_filter.to_dict(),
        summary=summarize_integration_registry(registry),
        items=catalog_items,
    )
