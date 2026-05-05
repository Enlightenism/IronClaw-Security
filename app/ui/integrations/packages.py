from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.adapter_manifest import (
    build_adapter_manifest,
    summarize_adapter_manifest,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)
from app.services.policy_bundle_signing import (
    PolicyBundle,
    initialize_policy_signing_keys,
    sign_policy_bundle,
    summarize_signed_bundle,
)


@dataclass(slots=True)
class IntegrationPackageItem:
    integration_id: str
    slug: str
    platform: str
    version: str
    manifest_summary: dict[str, Any] = field(default_factory=dict)
    bundle_summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "platform": self.platform,
            "version": self.version,
            "manifest_summary": dict(self.manifest_summary),
            "bundle_summary": dict(self.bundle_summary),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationPackagesView:
    title: str
    total: int
    items: list[IntegrationPackageItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_packages_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-packages",
) -> IntegrationPackagesView:
    records = list_integrations(registry)
    keyset = initialize_policy_signing_keys()
    items: list[IntegrationPackageItem] = []

    for record in records:
        manifest = build_adapter_manifest(
            record,
            extra_metadata={"requested_by": requested_by},
        )
        manifest_summary = summarize_adapter_manifest(manifest)

        bundle = PolicyBundle(
            bundle_id=f"bundle-{record.slug}",
            version=record.version,
            created_at=manifest.generated_at,
            policies=[
                {
                    "type": "adapter_manifest",
                    "integration_id": record.integration_id,
                    "slug": record.slug,
                    "manifest": manifest.to_dict(),
                }
            ],
            metadata={
                "integration_id": record.integration_id,
                "slug": record.slug,
                "platform": record.platform,
                "requested_by": requested_by,
            },
        )
        signed_bundle = sign_policy_bundle(bundle, keyset)
        bundle_summary = summarize_signed_bundle(signed_bundle)

        items.append(
            IntegrationPackageItem(
                integration_id=record.integration_id,
                slug=record.slug,
                platform=record.platform,
                version=record.version,
                manifest_summary=manifest_summary,
                bundle_summary=bundle_summary,
                metadata={
                    "requested_by": requested_by,
                    "status": record.status,
                },
            )
        )

    items.sort(key=lambda item: (item.platform, item.slug, item.integration_id))

    return IntegrationPackagesView(
        title="Integration Packages",
        total=len(items),
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )