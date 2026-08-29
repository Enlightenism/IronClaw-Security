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
from app.services.platform_capabilities import get_platform_profile


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
    capability_matrix: list[dict[str, Any]] = field(default_factory=list)
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
            "capability_matrix": [dict(item) for item in self.capability_matrix],
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


def _build_capability_matrix(record: Any, *, platform_profile: Any) -> list[dict[str, Any]]:
    profile_capabilities = {capability.name: capability for capability in getattr(platform_profile, "capabilities", [])}
    matrix: list[dict[str, Any]] = []

    for capability in getattr(record, "capabilities", []):
        capability_name = getattr(capability, "name", "")
        profile_capability = profile_capabilities.get(capability_name)
        support_level = "unsupported"
        details = getattr(capability, "details", "") or ""

        if profile_capability is not None:
            support_level = profile_capability.support
            details = profile_capability.details or details

        capability_entry = {
            "name": capability_name,
            "enabled": getattr(capability, "enabled", False),
            "support": support_level,
            "details": details,
        }
        matrix.append(capability_entry)

    return matrix


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
        capabilities = [capability.get("name") for capability in handshake.capabilities if isinstance(capability, dict) and capability.get("name")]
        platform_profile = get_platform_profile(record.platform)
        capability_matrix = _build_capability_matrix(record, platform_profile=platform_profile)
        supported_action_types: list[str] = []
        if hasattr(adapter, "supported_action_types"):
            supported_action_types = list(adapter.supported_action_types())  # type: ignore[attr-defined]

        total_capabilities += len(capability_matrix)

        items.append(
            IntegrationCapabilityItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                adapter_class=adapter.__class__.__name__,
                protocol_version=adapter.protocol_version,
                capability_count=len(capability_matrix),
                capabilities=capabilities,
                capability_matrix=capability_matrix,
                supported_action_types=supported_action_types,
                metadata={
                    "requested_by": requested_by,
                    "status": record.status,
                    "platform_support_summary": (
                        {
                            "platform": platform_profile.platform,
                            "display_name": platform_profile.display_name,
                            "install_mode": platform_profile.install_mode,
                        }
                        if platform_profile is not None
                        else None
                    ),
                },
            ),
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
