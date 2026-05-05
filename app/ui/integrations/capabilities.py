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
class IntegrationCapabilityItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    adapter_class: str
    protocol_version: str
    capability_count: int
    capabilities: list[str] = field(default_factory=list)
    supported_action_types: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "adapter_class": self.adapter_class,
            "protocol_version": self.protocol_version,
            "capability_count": self.capability_count,
            "capabilities": list(self.capabilities),
            "supported_action_types": list(self.supported_action_types),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationCapabilitiesView:
    title: str
    total: int
    total_capabilities: int
    items: list[IntegrationCapabilityItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "total_capabilities": self.total_capabilities,
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


def build_integration_capabilities_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-capabilities",
) -> IntegrationCapabilitiesView:
    records = list_integrations(registry)

    items: list[IntegrationCapabilityItem] = []
    total_capabilities = 0

    for record in records:
        adapter = _build_adapter_for_integration(
            record.integration_id,
            registry=registry,
        )
        if adapter is None:
            continue

        handshake = adapter.handshake()
        capabilities = list(handshake.capabilities)
        supported_action_types: list[str] = []
        if hasattr(adapter, "supported_action_types"):
            supported_action_types = list(adapter.supported_action_types())  # type: ignore[attr-defined]

        total_capabilities += len(capabilities)

        items.append(
            IntegrationCapabilityItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                adapter_class=adapter.__class__.__name__,
                protocol_version=adapter.protocol_version,
                capability_count=len(capabilities),
                capabilities=capabilities,
                supported_action_types=supported_action_types,
                metadata={
                    "requested_by": requested_by,
                    "status": record.status,
                },
            )
        )

    items.sort(key=lambda item: (item.platform, item.slug, item.integration_id))

    return IntegrationCapabilitiesView(
        title="Integration Capabilities",
        total=len(items),
        total_capabilities=total_capabilities,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )