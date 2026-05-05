from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
    list_integrations,
)
from app.services.platform_capabilities import (
    PlatformProfile,
    get_platform_profile,
    summarize_platform_profile,
)


@dataclass(slots=True)
class CompatibilityCheck:
    capability: str
    supported: bool
    support_level: str
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "supported": self.supported,
            "support_level": self.support_level,
            "details": self.details,
        }


@dataclass(slots=True)
class IntegrationCompatibilityItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    compatible: bool
    compatibility_score: int
    checks: list[CompatibilityCheck] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "compatible": self.compatible,
            "compatibility_score": self.compatibility_score,
            "checks": [check.to_dict() for check in self.checks],
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationCompatibilityView:
    title: str
    total: int
    compatible_count: int
    items: list[IntegrationCompatibilityItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "compatible_count": self.compatible_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _build_capability_map(profile: PlatformProfile | None) -> dict[str, dict[str, Any]]:
    if profile is None:
        return {}
    capability_map: dict[str, dict[str, Any]] = {}
    for capability in profile.capabilities:
        capability_map[capability.name] = {
            "support": capability.support,
            "details": capability.details,
        }
    return capability_map


def _build_compatibility_item(
    integration_id: str,
    *,
    registry: IntegrationRegistry,
) -> IntegrationCompatibilityItem:
    record = get_integration(registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    platform_profile = get_platform_profile(record.platform)
    capability_map = _build_capability_map(platform_profile)

    checks: list[CompatibilityCheck] = []
    passed_checks = 0

    for capability in record.capabilities:
        support_info = capability_map.get(
            capability.name,
            {"support": "unsupported", "details": "Capability not declared for platform."},
        )
        support_level = support_info["support"]
        supported = capability.enabled and support_level in {"native", "partial"}

        if not capability.enabled:
            supported = True
            support_level = "disabled"
            details = "Integration capability is disabled, so compatibility is not required."
        else:
            details = support_info["details"]

        if supported:
            passed_checks += 1

        checks.append(
            CompatibilityCheck(
                capability=capability.name,
                supported=supported,
                support_level=support_level,
                details=details,
            )
        )

    compatibility_score = int((passed_checks / len(checks)) * 100) if checks else 100
    compatible = all(check.supported for check in checks)

    metadata = {
        "integration_status": record.status,
        "integration_type": record.integration_type,
    }
    if platform_profile is not None:
        metadata["platform_summary"] = summarize_platform_profile(platform_profile)

    return IntegrationCompatibilityItem(
        integration_id=record.integration_id,
        slug=record.slug,
        name=record.name,
        platform=record.platform,
        compatible=compatible,
        compatibility_score=compatibility_score,
        checks=checks,
        metadata=metadata,
    )


def build_integration_compatibility_view(
    *,
    registry: IntegrationRegistry,
) -> IntegrationCompatibilityView:
    records = list_integrations(registry)

    items = [
        _build_compatibility_item(record.integration_id, registry=registry)
        for record in records
    ]
    compatible_count = sum(1 for item in items if item.compatible)

    return IntegrationCompatibilityView(
        title="Integration Compatibility",
        total=len(items),
        compatible_count=compatible_count,
        items=items,
        metadata={},
    )