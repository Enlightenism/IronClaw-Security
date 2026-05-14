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
class IntegrationMatrixItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    protocol_version: str
    supports_install: bool
    supports_endpoint: bool
    supports_actions: bool
    supports_capabilities: bool
    supported_action_types: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    compatibility_score: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "protocol_version": self.protocol_version,
            "supports_install": self.supports_install,
            "supports_endpoint": self.supports_endpoint,
            "supports_actions": self.supports_actions,
            "supports_capabilities": self.supports_capabilities,
            "supported_action_types": list(self.supported_action_types),
            "capabilities": list(self.capabilities),
            "compatibility_score": self.compatibility_score,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationMatrixView:
    title: str
    total: int
    high_compatibility_count: int
    medium_compatibility_count: int
    low_compatibility_count: int
    items: list[IntegrationMatrixItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "high_compatibility_count": self.high_compatibility_count,
            "medium_compatibility_count": self.medium_compatibility_count,
            "low_compatibility_count": self.low_compatibility_count,
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


def _compatibility_score(
    *,
    status: str,
    supports_install: bool,
    supports_endpoint: bool,
    supports_actions: bool,
    supports_capabilities: bool,
    action_count: int,
    capability_count: int,
) -> int:
    score = 0

    if status == "active":
        score += 20
    elif status in {"planned", "draft"}:
        score += 10

    if supports_install:
        score += 20
    if supports_endpoint:
        score += 20
    if supports_actions:
        score += 20
    if supports_capabilities:
        score += 10

    score += min(action_count * 2, 5)
    score += min(capability_count, 5)

    return max(0, min(score, 100))


def build_integration_matrix_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-matrix",
) -> IntegrationMatrixView:
    records = list_integrations(registry)

    items: list[IntegrationMatrixItem] = []
    high_compatibility_count = 0
    medium_compatibility_count = 0
    low_compatibility_count = 0

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
        supported_action_types_method = getattr(adapter, "supported_action_types", None)
        if callable(supported_action_types_method):
            supported_action_types = list(supported_action_types_method())

        supports_install = bool(getattr(record, "install_target", None))
        supports_endpoint = bool(
            getattr(record, "endpoint", None) or getattr(record, "base_url", None),
        )
        supports_actions = len(supported_action_types) > 0
        supports_capabilities = len(capabilities) > 0

        score = _compatibility_score(
            status=record.status,
            supports_install=supports_install,
            supports_endpoint=supports_endpoint,
            supports_actions=supports_actions,
            supports_capabilities=supports_capabilities,
            action_count=len(supported_action_types),
            capability_count=len(capabilities),
        )

        if score >= 75:
            high_compatibility_count += 1
        elif score >= 45:
            medium_compatibility_count += 1
        else:
            low_compatibility_count += 1

        items.append(
            IntegrationMatrixItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                protocol_version=adapter.protocol_version,
                supports_install=supports_install,
                supports_endpoint=supports_endpoint,
                supports_actions=supports_actions,
                supports_capabilities=supports_capabilities,
                supported_action_types=supported_action_types,
                capabilities=capabilities,
                compatibility_score=score,
                metadata={
                    "requested_by": requested_by,
                    "adapter_class": adapter.__class__.__name__,
                },
            ),
        )

    items.sort(
        key=lambda item: (
            -item.compatibility_score,
            item.platform,
            item.slug,
            item.integration_id,
        ),
    )

    return IntegrationMatrixView(
        title="Integration Matrix",
        total=len(items),
        high_compatibility_count=high_compatibility_count,
        medium_compatibility_count=medium_compatibility_count,
        low_compatibility_count=low_compatibility_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
