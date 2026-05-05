from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.adapters.base import AdapterHandshake, BaseIntegrationAdapter
from app.adapters.generic_agent_adapter import GenericAgentAdapter
from app.adapters.mcp_tool_adapter import McpToolAdapter
from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
    list_integrations,
)


@dataclass(slots=True)
class AdapterSummaryItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    adapter_class: str
    protocol_version: str
    health: str
    capability_count: int
    supported_action_types: list[str] = field(default_factory=list)
    handshake: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "adapter_class": self.adapter_class,
            "protocol_version": self.protocol_version,
            "health": self.health,
            "capability_count": self.capability_count,
            "supported_action_types": list(self.supported_action_types),
            "handshake": dict(self.handshake),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationAdaptersView:
    title: str
    total: int
    items: list[AdapterSummaryItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
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


def _adapter_class_name(adapter: BaseIntegrationAdapter) -> str:
    return adapter.__class__.__name__


def build_integration_adapters_view(
    *,
    registry: IntegrationRegistry,
) -> IntegrationAdaptersView:
    records = list_integrations(registry)
    items: list[AdapterSummaryItem] = []

    for record in records:
        adapter = _build_adapter_for_integration(record.integration_id, registry=registry)
        if adapter is None:
            continue

        handshake: AdapterHandshake = adapter.handshake()
        supported_action_types = []
        if hasattr(adapter, "supported_action_types"):
            supported_action_types = list(adapter.supported_action_types())  # type: ignore[attr-defined]

        items.append(
            AdapterSummaryItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                adapter_class=_adapter_class_name(adapter),
                protocol_version=adapter.protocol_version,
                health=adapter.health,
                capability_count=len(handshake.capabilities),
                supported_action_types=supported_action_types,
                handshake=handshake.to_dict(),
                metadata=dict(adapter.metadata),
            )
        )

    items.sort(key=lambda item: (item.platform, item.slug, item.integration_id))

    return IntegrationAdaptersView(
        title="Integration Adapters",
        total=len(items),
        items=items,
        metadata={},
    )