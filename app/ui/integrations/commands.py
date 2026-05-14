from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)


def _normalize_status(value: str | None) -> str:
    if not value:
        return "unknown"
    return value.strip().lower()


def _command_kind(*, install_target: str | None, metadata: dict[str, Any]) -> str:
    if install_target:
        return "installer"
    if metadata.get("diagnostic") is True:
        return "diagnostic"
    return "utility"


def _command_health(*, status: str) -> str:
    if status == "active":
        return "ready"
    if status in {"planned", "draft"}:
        return "planned"
    if status in {"disabled", "inactive"}:
        return "inactive"
    return "unknown"


@dataclass(slots=True)
class IntegrationCommandItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    command_name: str
    command_kind: str
    install_target: str | None = None
    status: str = "planned"
    health: str = "unknown"
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "command_name": self.command_name,
            "command_kind": self.command_kind,
            "install_target": self.install_target,
            "status": self.status,
            "health": self.health,
            "description": self.description,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationCommandView:
    title: str
    total: int
    installer_count: int
    diagnostic_count: int
    utility_count: int
    ready_count: int
    planned_count: int
    items: list[IntegrationCommandItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "installer_count": self.installer_count,
            "diagnostic_count": self.diagnostic_count,
            "utility_count": self.utility_count,
            "ready_count": self.ready_count,
            "planned_count": self.planned_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_commands_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-commands",
) -> IntegrationCommandView:
    records = list_integrations(registry)

    items: list[IntegrationCommandItem] = []
    installer_count = 0
    diagnostic_count = 0
    utility_count = 0
    ready_count = 0
    planned_count = 0

    for record in records:
        command_name = getattr(record, "command_name", None)
        if not command_name:
            continue

        install_target = getattr(record, "install_target", None)
        status = _normalize_status(getattr(record, "status", None))
        record_metadata = dict(getattr(record, "metadata", {}) or {})

        command_kind = _command_kind(
            install_target=install_target,
            metadata=record_metadata,
        )
        health = _command_health(status=status)

        if command_kind == "installer":
            installer_count += 1
        elif command_kind == "diagnostic":
            diagnostic_count += 1
        else:
            utility_count += 1

        if health == "ready":
            ready_count += 1
        elif health == "planned":
            planned_count += 1

        items.append(
            IntegrationCommandItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                command_name=command_name,
                command_kind=command_kind,
                install_target=install_target,
                status=record.status,
                health=health,
                description=getattr(record, "description", "") or "",
                metadata={
                    **record_metadata,
                    "requested_by": requested_by,
                },
            ),
        )

    items.sort(
        key=lambda item: (
            item.command_kind != "installer",
            item.health != "ready",
            item.platform,
            item.name,
            item.integration_id,
        ),
    )

    return IntegrationCommandView(
        title="Integration Commands",
        total=len(items),
        installer_count=installer_count,
        diagnostic_count=diagnostic_count,
        utility_count=utility_count,
        ready_count=ready_count,
        planned_count=planned_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
