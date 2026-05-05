from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.services.integration_registry import IntegrationCapability, IntegrationRecord


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class AdapterManifest:
    manifest_version: str
    generated_at: str
    integration_id: str
    slug: str
    platform: str
    name: str
    version: str
    command_name: str | None
    entrypoint: str | None
    install_target: str | None
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "generated_at": self.generated_at,
            "integration_id": self.integration_id,
            "slug": self.slug,
            "platform": self.platform,
            "name": self.name,
            "version": self.version,
            "command_name": self.command_name,
            "entrypoint": self.entrypoint,
            "install_target": self.install_target,
            "capabilities": list(self.capabilities),
            "metadata": dict(self.metadata),
        }


def _serialize_capabilities(
    capabilities: list[IntegrationCapability],
) -> list[dict[str, Any]]:
    return [capability.to_dict() for capability in capabilities]


def build_adapter_manifest(
    record: IntegrationRecord,
    *,
    manifest_version: str = "1.0.0",
    extra_metadata: dict[str, Any] | None = None,
) -> AdapterManifest:
    metadata = dict(record.metadata)
    metadata.update(extra_metadata or {})

    return AdapterManifest(
        manifest_version=manifest_version,
        generated_at=_utc_now(),
        integration_id=record.integration_id,
        slug=record.slug,
        platform=record.platform,
        name=record.name,
        version=record.version,
        command_name=record.command_name,
        entrypoint=record.entrypoint,
        install_target=record.install_target,
        capabilities=_serialize_capabilities(record.capabilities),
        metadata=metadata,
    )


def summarize_adapter_manifest(manifest: AdapterManifest) -> dict[str, Any]:
    return {
        "manifest_version": manifest.manifest_version,
        "integration_id": manifest.integration_id,
        "slug": manifest.slug,
        "platform": manifest.platform,
        "version": manifest.version,
        "capability_count": len(manifest.capabilities),
        "generated_at": manifest.generated_at,
    }