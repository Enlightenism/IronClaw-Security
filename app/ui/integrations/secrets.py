from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)
from app.services.secrets_redaction import (
    RedactionRuleSummary,
    SecretsRedactionConfig,
    build_default_redaction_config,
    summarize_redaction_config,
)


@dataclass(slots=True)
class IntegrationSecretItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    has_secrets: bool
    secret_sources: list[str] = field(default_factory=list)
    redaction_rules: list[RedactionRuleSummary] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "has_secrets": self.has_secrets,
            "secret_sources": list(self.secret_sources),
            "redaction_rules": [rule.to_dict() for rule in self.redaction_rules],
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationSecretsView:
    title: str
    total: int
    with_secrets_count: int
    items: list[IntegrationSecretItem] = field(default_factory=list)
    redaction_summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "with_secrets_count": self.with_secrets_count,
            "items": [item.to_dict() for item in self.items],
            "redaction_summary": dict(self.redaction_summary),
            "metadata": dict(self.metadata),
        }


def _infer_secret_sources(metadata: dict[str, Any]) -> list[str]:
    sources: list[str] = []
    if metadata.get("supports_local_runtime"):
        sources.append("local_env")
    if metadata.get("transport") == "http":
        sources.append("http_headers")
    if metadata.get("supports_builder_mode"):
        sources.append("builder_config")
    if metadata.get("one_command_install"):
        sources.append("installer_config")
    return sources


def build_integration_secrets_view(
    *,
    registry: IntegrationRegistry,
    redaction_config: SecretsRedactionConfig | None = None,
    requested_by: str = "ui-secrets",
) -> IntegrationSecretsView:
    records = list_integrations(registry)
    active_config = redaction_config or build_default_redaction_config()
    redaction_summary = summarize_redaction_config(active_config)

    items: list[IntegrationSecretItem] = []
    with_secrets_count = 0

    for record in records:
        secret_sources = _infer_secret_sources(record.metadata)
        has_secrets = bool(secret_sources)

        if has_secrets:
            with_secrets_count += 1

        items.append(
            IntegrationSecretItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                has_secrets=has_secrets,
                secret_sources=secret_sources,
                redaction_rules=list(active_config.rules),
                metadata={
                    "status": record.status,
                    "requested_by": requested_by,
                },
            ),
        )

    items.sort(key=lambda item: (item.platform, item.name, item.integration_id))

    return IntegrationSecretsView(
        title="Integration Secrets",
        total=len(items),
        with_secrets_count=with_secrets_count,
        items=items,
        redaction_summary=redaction_summary,
        metadata={
            "requested_by": requested_by,
        },
    )
