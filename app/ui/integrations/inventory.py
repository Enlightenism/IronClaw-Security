from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)


@dataclass(slots=True)
class IntegrationInventoryItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    version: str
    integration_type: str
    command_name: str | None
    install_target: str | None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "version": self.version,
            "integration_type": self.integration_type,
            "command_name": self.command_name,
            "install_target": self.install_target,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationInventoryView:
    title: str
    total: int
    active_count: int
    planned_count: int
    disabled_count: int
    items: list[IntegrationInventoryItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "active_count": self.active_count,
            "planned_count": self.planned_count,
            "disabled_count": self.disabled_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _status_bucket(status: str | None) -> str:
    value = (status or "").strip().lower()
    if value in {"active", "enabled"}:
        return "active"
    if value in {"planned", "draft"}:
        return "planned"
    if value in {"disabled", "inactive"}:
        return "disabled"
    return "unknown"


def build_integration_inventory_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-inventory",
) -> IntegrationInventoryView:
    records = list_integrations(registry)

    items: list[IntegrationInventoryItem] = []
    active_count = 0
    planned_count = 0
    disabled_count = 0

    for record in records:
        bucket = _status_bucket(getattr(record, "status", None))
        if bucket == "active":
            active_count += 1
        elif bucket == "planned":
            planned_count += 1
        elif bucket == "disabled":
            disabled_count += 1

        tags: list[str] = []
        integration_type = getattr(record, "integration_type", "unknown") or "unknown"
        tags.append(f"type:{integration_type}")
        if getattr(record, "command_name", None):
            tags.append("one-command")
        if getattr(record, "install_target", None):
            tags.append("installable")

        items.append(
            IntegrationInventoryItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                version=record.version,
                integration_type=integration_type,
                command_name=getattr(record, "command_name", None),
                install_target=getattr(record, "install_target", None),
                tags=tags,
                metadata={
                    "requested_by": requested_by,
                },
            ),
        )

    items.sort(
        key=lambda item: (
            0 if _status_bucket(item.status) == "active" else 1 if _status_bucket(item.status) == "planned" else 2 if _status_bucket(item.status) == "disabled" else 3,
            item.platform,
            item.slug,
            item.integration_id,
        ),
    )

    return IntegrationInventoryView(
        title="Integration Inventory",
        total=len(items),
        active_count=active_count,
        planned_count=planned_count,
        disabled_count=disabled_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
