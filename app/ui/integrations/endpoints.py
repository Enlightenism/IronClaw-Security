from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)


@dataclass(slots=True)
class IntegrationEndpointItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    endpoint: str | None
    base_url: str | None
    command_name: str | None
    install_target: str | None
    endpoint_kind: str
    is_configured: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "endpoint": self.endpoint,
            "base_url": self.base_url,
            "command_name": self.command_name,
            "install_target": self.install_target,
            "endpoint_kind": self.endpoint_kind,
            "is_configured": self.is_configured,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationEndpointsView:
    title: str
    total: int
    configured_count: int
    local_count: int
    remote_count: int
    items: list[IntegrationEndpointItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "configured_count": self.configured_count,
            "local_count": self.local_count,
            "remote_count": self.remote_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _endpoint_kind(endpoint: str | None, base_url: str | None) -> str:
    value = endpoint or base_url or ""
    normalized = value.strip().lower()

    if not normalized:
        return "none"
    if normalized.startswith("local://"):
        return "local"
    if normalized.startswith("http://") or normalized.startswith("https://"):
        return "remote"
    return "custom"


def build_integration_endpoints_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-endpoints",
) -> IntegrationEndpointsView:
    records = list_integrations(registry)

    items: list[IntegrationEndpointItem] = []
    configured_count = 0
    local_count = 0
    remote_count = 0

    for record in records:
        endpoint = getattr(record, "endpoint", None)
        base_url = getattr(record, "base_url", None)
        endpoint_kind = _endpoint_kind(endpoint, base_url)
        is_configured = bool(endpoint or base_url)

        if is_configured:
            configured_count += 1
        if endpoint_kind == "local":
            local_count += 1
        elif endpoint_kind == "remote":
            remote_count += 1

        items.append(
            IntegrationEndpointItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                endpoint=endpoint,
                base_url=base_url,
                command_name=getattr(record, "command_name", None),
                install_target=getattr(record, "install_target", None),
                endpoint_kind=endpoint_kind,
                is_configured=is_configured,
                metadata={
                    "requested_by": requested_by,
                },
            )
        )

    items.sort(
        key=lambda item: (
            0 if item.endpoint_kind == "remote"
            else 1 if item.endpoint_kind == "local"
            else 2 if item.endpoint_kind == "custom"
            else 3,
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationEndpointsView(
        title="Integration Endpoints",
        total=len(items),
        configured_count=configured_count,
        local_count=local_count,
        remote_count=remote_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )