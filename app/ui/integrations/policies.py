from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.adapter_manifest import build_adapter_manifest
from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)
from app.services.policy_bundle_signing import (
    PolicyBundle,
    initialize_policy_signing_keys,
    sign_policy_bundle,
    summarize_signed_bundle,
    verify_policy_bundle_signature,
)


@dataclass(slots=True)
class IntegrationPolicyItem:
    integration_id: str
    slug: str
    platform: str
    version: str
    policy_count: int
    status: str
    signature_status: str
    bundle_summary: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "platform": self.platform,
            "version": self.version,
            "policy_count": self.policy_count,
            "status": self.status,
            "signature_status": self.signature_status,
            "bundle_summary": dict(self.bundle_summary),
            "verification": dict(self.verification),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationPoliciesView:
    title: str
    total: int
    valid_bundle_count: int
    invalid_bundle_count: int
    items: list[IntegrationPolicyItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "valid_bundle_count": self.valid_bundle_count,
            "invalid_bundle_count": self.invalid_bundle_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_policies_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-policies",
) -> IntegrationPoliciesView:
    keyset = initialize_policy_signing_keys()
    records = list_integrations(registry)

    items: list[IntegrationPolicyItem] = []
    valid_bundle_count = 0
    invalid_bundle_count = 0

    for record in records:
        manifest = build_adapter_manifest(
            record,
            extra_metadata={"requested_by": requested_by},
        )

        policies = [
            {
                "type": "adapter_manifest",
                "integration_id": record.integration_id,
                "slug": record.slug,
                "manifest_version": manifest.manifest_version,
                "capabilities": list(manifest.capabilities),
            }
        ]

        bundle = PolicyBundle(
            bundle_id=f"bundle-{record.slug}",
            version=record.version,
            created_at=manifest.generated_at,
            policies=policies,
            metadata={
                "integration_id": record.integration_id,
                "slug": record.slug,
                "platform": record.platform,
                "requested_by": requested_by,
            },
        )

        signed_bundle = sign_policy_bundle(bundle, keyset)
        verification = verify_policy_bundle_signature(signed_bundle, keyset)
        bundle_summary = summarize_signed_bundle(
            signed_bundle,
            verification=verification,
        )

        signature_status = verification.status
        if signature_status == "valid":
            valid_bundle_count += 1
        else:
            invalid_bundle_count += 1

        items.append(
            IntegrationPolicyItem(
                integration_id=record.integration_id,
                slug=record.slug,
                platform=record.platform,
                version=record.version,
                policy_count=len(bundle.policies),
                status=record.status,
                signature_status=signature_status,
                bundle_summary=bundle_summary,
                verification=verification.to_dict(),
                metadata={
                    "requested_by": requested_by,
                },
            )
        )

    items.sort(
        key=lambda item: (
            0 if item.signature_status == "valid" else 1,
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationPoliciesView(
        title="Integration Policies",
        total=len(items),
        valid_bundle_count=valid_bundle_count,
        invalid_bundle_count=invalid_bundle_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )