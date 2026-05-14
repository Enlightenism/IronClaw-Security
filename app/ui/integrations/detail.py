from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.adapter_manifest import (
    build_adapter_manifest,
    summarize_adapter_manifest,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
)
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)
from app.services.platform_capabilities import get_platform_profile


@dataclass(slots=True)
class IntegrationDetailSection:
    title: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "data": dict(self.data),
        }


@dataclass(slots=True)
class IntegrationDetailView:
    integration_id: str
    slug: str
    title: str
    status: str
    platform: str
    version: str
    sections: list[IntegrationDetailSection] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "title": self.title,
            "status": self.status,
            "platform": self.platform,
            "version": self.version,
            "sections": [section.to_dict() for section in self.sections],
            "metadata": dict(self.metadata),
        }


def build_integration_detail_view(
    integration_id: str,
    *,
    registry: IntegrationRegistry,
    strict_verification: bool = False,
) -> IntegrationDetailView:
    record = get_integration(registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    manifest = build_adapter_manifest(record)
    manifest_summary = summarize_adapter_manifest(manifest)

    verification = verify_integration(
        registry,
        integration_id,
        strict=strict_verification,
        requested_by="ui-detail",
    )
    verification_summary = summarize_verification_result(verification)

    platform_profile = get_platform_profile(record.platform)
    platform_data = (
        platform_profile.to_dict()
        if platform_profile is not None
        else {
            "platform": record.platform,
            "display_name": record.platform,
            "install_mode": "unknown",
            "capabilities": [],
            "metadata": {},
            "checked_at": None,
        }
    )

    sections = [
        IntegrationDetailSection(
            title="Overview",
            data={
                "integration_id": record.integration_id,
                "name": record.name,
                "slug": record.slug,
                "description": record.description,
                "integration_type": record.integration_type,
                "status": record.status,
                "version": record.version,
                "command_name": record.command_name,
                "entrypoint": record.entrypoint,
                "install_target": record.install_target,
            },
        ),
        IntegrationDetailSection(
            title="Capabilities",
            data={
                "enabled": [capability.to_dict() for capability in record.capabilities if capability.enabled],
                "disabled": [capability.to_dict() for capability in record.capabilities if not capability.enabled],
            },
        ),
        IntegrationDetailSection(
            title="Manifest",
            data={
                "summary": manifest_summary,
                "full": manifest.to_dict(),
            },
        ),
        IntegrationDetailSection(
            title="Verification",
            data={
                "summary": verification_summary,
                "full": verification.to_dict(),
            },
        ),
        IntegrationDetailSection(
            title="Platform",
            data=platform_data,
        ),
        IntegrationDetailSection(
            title="Metadata",
            data=dict(record.metadata),
        ),
    ]

    return IntegrationDetailView(
        integration_id=record.integration_id,
        slug=record.slug,
        title=record.name,
        status=record.status,
        platform=record.platform,
        version=record.version,
        sections=sections,
        metadata={
            "strict_verification": strict_verification,
        },
    )
