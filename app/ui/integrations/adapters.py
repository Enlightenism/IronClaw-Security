from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.adapters.base import AdapterHandshake, BaseIntegrationAdapter
from app.adapters.generic_agent_adapter import GenericAgentAdapter
from app.adapters.mcp_tool_adapter import McpToolAdapter
from app.core.install_key_formats import (
    get_install_key_format_spec,
    iter_supported_install_key_programs,
    normalize_install_key_program,
)
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
    capability_pills: list[str] = field(default_factory=list)
    platform_cards: list[str] = field(default_factory=list)
    install_key_program: str | None = None
    install_key_family: str | None = None
    install_key_prefix: str | None = None
    install_key_aliases: list[str] = field(default_factory=list)
    shared_install_key_family: bool = False
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
            "capability_pills": list(self.capability_pills),
            "platform_cards": list(self.platform_cards),
            "install_key_program": self.install_key_program,
            "install_key_family": self.install_key_family,
            "install_key_prefix": self.install_key_prefix,
            "install_key_aliases": list(self.install_key_aliases),
            "shared_install_key_family": self.shared_install_key_family,
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


def _canonical_runtime_cards() -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for program in iter_supported_install_key_programs():
        spec = get_install_key_format_spec(program)
        cards.append(
            {
                "platform": spec.platform_aliases[0] if spec.platform_aliases else spec.program,
                "display_name": spec.display_name,
                "install_key_program": spec.program,
                "install_key_family": spec.family,
                "install_key_prefix": spec.prefix,
                "platform_aliases": list(spec.platform_aliases),
                "shared_install_key_family": len(spec.platform_aliases) > 1 or spec.program == "security_guardian",
            },
        )
    return cards


def _record_runtime_metadata(record: Any) -> dict[str, Any]:
    candidates = [
        getattr(record, "platform", None),
        getattr(record, "slug", None),
        (getattr(record, "metadata", {}) or {}).get("runtime"),
        (getattr(record, "metadata", {}) or {}).get("install_key_program"),
        (getattr(record, "metadata", {}) or {}).get("platform"),
    ]

    install_key_program = None
    install_key_family = None
    install_key_prefix = None
    install_key_aliases: list[str] = []
    shared_install_key_family = False

    for candidate in candidates:
        normalized = normalize_install_key_program(candidate)
        if normalized is None:
            continue
        install_key_program = normalized
        spec = get_install_key_format_spec(normalized)
        install_key_family = spec.family
        install_key_prefix = spec.prefix
        install_key_aliases = list(spec.platform_aliases)
        shared_install_key_family = len(spec.platform_aliases) > 1 or spec.program == "security_guardian"
        break

    if install_key_program is None:
        install_key_program = normalize_install_key_program(record.platform)
        if install_key_program is not None:
            spec = get_install_key_format_spec(install_key_program)
            install_key_family = spec.family
            install_key_prefix = spec.prefix
            install_key_aliases = list(spec.platform_aliases)
            shared_install_key_family = len(spec.platform_aliases) > 1 or spec.program == "security_guardian"

    return {
        "install_key_program": install_key_program,
        "install_key_family": install_key_family,
        "install_key_prefix": install_key_prefix,
        "install_key_aliases": install_key_aliases,
        "shared_install_key_family": shared_install_key_family,
    }


def build_integration_adapters_view(
    *,
    registry: IntegrationRegistry,
) -> IntegrationAdaptersView:
    records = list_integrations(registry)
    items: list[AdapterSummaryItem] = []
    runtime_cards = _canonical_runtime_cards()

    for record in records:
        adapter = _build_adapter_for_integration(record.integration_id, registry=registry)
        if adapter is None:
            continue

        handshake: AdapterHandshake = adapter.handshake()
        supported_action_types = []
        if hasattr(adapter, "supported_action_types"):
            supported_action_types = list(adapter.supported_action_types())  # type: ignore[attr-defined]

        capability_pills = [capability.get("name") for capability in handshake.capabilities if isinstance(capability, dict) and capability.get("name")]
        runtime_metadata = _record_runtime_metadata(record)
        install_key_aliases = list(runtime_metadata["install_key_aliases"]) or [record.platform]
        platform_cards = list(dict.fromkeys([record.platform, *install_key_aliases, record.slug]))

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
                capability_pills=capability_pills,
                platform_cards=platform_cards,
                install_key_program=runtime_metadata["install_key_program"],
                install_key_family=runtime_metadata["install_key_family"],
                install_key_prefix=runtime_metadata["install_key_prefix"],
                install_key_aliases=install_key_aliases,
                shared_install_key_family=runtime_metadata["shared_install_key_family"],
                handshake=handshake.to_dict(),
                metadata={
                    **dict(adapter.metadata),
                    "runtime_cards": platform_cards,
                    "capability_pills": capability_pills,
                    **runtime_metadata,
                },
            ),
        )

    items.sort(key=lambda item: (item.platform, item.slug, item.integration_id))

    return IntegrationAdaptersView(
        title="Integration Adapters",
        total=len(items),
        items=items,
        metadata={
            "supported_runtime_cards": runtime_cards,
            "runtime_card_count": len(runtime_cards),
            "supported_runtime_programs": [card["install_key_program"] for card in runtime_cards],
        },
    )
