from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.adapters.base import BaseIntegrationAdapter
from app.adapters.generic_agent_adapter import GenericAgentAdapter
from app.adapters.mcp_tool_adapter import McpToolAdapter
from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
    list_integrations,
)


@dataclass(slots=True)
class IntegrationDependencyItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    adapter_class: str
    dependency_count: int
    dependencies: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "adapter_class": self.adapter_class,
            "dependency_count": self.dependency_count,
            "dependencies": list(self.dependencies),
            "capabilities": list(self.capabilities),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationDependenciesView:
    title: str
    total: int
    total_dependencies: int
    items: list[IntegrationDependencyItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "total_dependencies": self.total_dependencies,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _build_adapter_for_integration(
    integration_id: str,
    *,
    registry: IntegrationRegistry,
) -> BaseIntegrationAdapter | None:
    record = get_integration(registry, integration_id)
    if record is None:
        return None

    if record.slug == "generic-agent":
        return GenericAgentAdapter(record=record)
    if record.slug == "openclaw":
        return McpToolAdapter(record=record)
    if record.slug == "claude-code":
        return GenericAgentAdapter(record=record, runtime="claude-code")

    return BaseIntegrationAdapter(record=record)


def _derive_dependencies(record: Any, adapter: BaseIntegrationAdapter) -> list[str]:
    dependencies: list[str] = []

    command_name = getattr(record, "command_name", None)
    install_target = getattr(record, "install_target", None)
    endpoint = getattr(record, "endpoint", None) or getattr(record, "base_url", None)

    if command_name:
        dependencies.append(f"command:{command_name}")
    if install_target:
        dependencies.append(f"install:{install_target}")
    if endpoint:
        dependencies.append(f"endpoint:{endpoint}")

    handshake = adapter.handshake()
    for capability in handshake.capabilities:
        dependencies.append(f"capability:{capability}")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in dependencies:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)

    return deduped


def build_integration_dependencies_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-dependencies",
) -> IntegrationDependenciesView:
    records = list_integrations(registry)

    items: list[IntegrationDependencyItem] = []
    total_dependencies = 0

    for record in records:
        adapter = _build_adapter_for_integration(
            record.integration_id,
            registry=registry,
        )
        if adapter is None:
            continue

        handshake = adapter.handshake()
        dependencies = _derive_dependencies(record, adapter)
        total_dependencies += len(dependencies)

        items.append(
            IntegrationDependencyItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                adapter_class=adapter.__class__.__name__,
                dependency_count=len(dependencies),
                dependencies=dependencies,
                capabilities=list(handshake.capabilities),
                metadata={
                    "requested_by": requested_by,
                    "status": record.status,
                },
            )
        )

    items.sort(
        key=lambda item: (
            -item.dependency_count,
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationDependenciesView(
        title="Integration Dependencies",
        total=len(items),
        total_dependencies=total_dependencies,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )