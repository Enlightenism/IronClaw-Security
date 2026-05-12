from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
    summarize_integration_registry,
)
from app.services.platform_capabilities import (
    PlatformProfile,
    default_platform_profiles,
    list_platform_profiles,
    summarize_platform_profile,
)


@dataclass(slots=True)
class PlatformIntegrationSummary:
    platform: str
    display_name: str
    install_mode: str
    integration_count: int
    active_integrations: int
    planned_integrations: int
    disabled_integrations: int
    deprecated_integrations: int
    capabilities: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "display_name": self.display_name,
            "install_mode": self.install_mode,
            "integration_count": self.integration_count,
            "active_integrations": self.active_integrations,
            "planned_integrations": self.planned_integrations,
            "disabled_integrations": self.disabled_integrations,
            "deprecated_integrations": self.deprecated_integrations,
            "capabilities": dict(self.capabilities),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PlatformProfileItem:
    platform: str
    display_name: str
    install_mode: str
    capability_count: int
    native_capabilities: int
    partial_capabilities: int
    unsupported_capabilities: int
    integration_summary: PlatformIntegrationSummary
    profile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "display_name": self.display_name,
            "install_mode": self.install_mode,
            "capability_count": self.capability_count,
            "native_capabilities": self.native_capabilities,
            "partial_capabilities": self.partial_capabilities,
            "unsupported_capabilities": self.unsupported_capabilities,
            "integration_summary": self.integration_summary.to_dict(),
            "profile": dict(self.profile),
        }


@dataclass(slots=True)
class PlatformsView:
    title: str
    total: int
    items: list[PlatformProfileItem] = field(default_factory=list)
    registry_summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "items": [item.to_dict() for item in self.items],
            "registry_summary": dict(self.registry_summary),
            "metadata": dict(self.metadata),
        }


def _build_platform_integration_summary(
    platform: str,
    *,
    registry: IntegrationRegistry,
) -> PlatformIntegrationSummary:
    records = [
        record
        for record in list_integrations(registry)
        if record.platform.strip().lower() == platform.strip().lower()
    ]

    status_counts: dict[str, int] = {
        "active": 0,
        "planned": 0,
        "disabled": 0,
        "deprecated": 0,
    }
    capability_counts: dict[str, int] = {}

    for record in records:
        status_counts[record.status] = status_counts.get(record.status, 0) + 1
        for capability in record.capabilities:
            if capability.enabled:
                capability_counts[capability.name] = capability_counts.get(
                    capability.name, 0
                ) + 1

    if records:
        display_name = records[0].platform
        install_mode = records[0].install_target or "local"
    else:
        default_profiles = {p.platform: p for p in default_platform_profiles()}
        profile = default_profiles.get(platform)
        display_name = profile.display_name if profile else platform
        install_mode = profile.install_mode if profile else "unknown"

    return PlatformIntegrationSummary(
        platform=platform,
        display_name=display_name,
        install_mode=install_mode,
        integration_count=len(records),
        active_integrations=status_counts.get("active", 0),
        planned_integrations=status_counts.get("planned", 0),
        disabled_integrations=status_counts.get("disabled", 0),
        deprecated_integrations=status_counts.get("deprecated", 0),
        capabilities=capability_counts,
        metadata={},
    )


def build_platforms_view(
    *,
    registry: IntegrationRegistry,
) -> PlatformsView:
    profiles: list[PlatformProfile] = list_platform_profiles()
    registry_summary = summarize_integration_registry(registry)

    items: list[PlatformProfileItem] = []

    for profile in profiles:
        platform_summary = summarize_platform_profile(profile)
        integration_summary = _build_platform_integration_summary(
            profile.platform,
            registry=registry,
        )

        items.append(
            PlatformProfileItem(
                platform=profile.platform,
                display_name=profile.display_name,
                install_mode=profile.install_mode,
                capability_count=platform_summary["capability_count"],
                native_capabilities=platform_summary["native_capabilities"],
                partial_capabilities=platform_summary["partial_capabilities"],
                unsupported_capabilities=platform_summary["unsupported_capabilities"],
                integration_summary=integration_summary,
                profile=profile.to_dict(),
            )
        )

    # Ensure any platforms present in the registry but missing a profile still appear.
    known_platforms = {item.platform for item in items}
    for record in list_integrations(registry):
        if record.platform in known_platforms:
            continue
        integration_summary = _build_platform_integration_summary(
            record.platform,
            registry=registry,
        )
        items.append(
            PlatformProfileItem(
                platform=record.platform,
                display_name=record.platform,
                install_mode=record.install_target or "local",
                capability_count=0,
                native_capabilities=0,
                partial_capabilities=0,
                unsupported_capabilities=0,
                integration_summary=integration_summary,
                profile={
                    "platform": record.platform,
                    "display_name": record.platform,
                    "install_mode": record.install_target or "local",
                    "capabilities": [],
                    "metadata": {},
                    "checked_at": None,
                },
            )
        )

    items.sort(key=lambda item: item.platform)

    return PlatformsView(
        title="Integration Platforms",
        total=len(items),
        items=items,
        registry_summary=registry_summary,
        metadata={},
    )