from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)


@dataclass(slots=True)
class IntegrationOverviewItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    version: str
    verified: bool
    health: str
    command_ready: bool
    install_ready: bool
    endpoint_ready: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "version": self.version,
            "verified": self.verified,
            "health": self.health,
            "command_ready": self.command_ready,
            "install_ready": self.install_ready,
            "endpoint_ready": self.endpoint_ready,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationOverviewView:
    title: str
    total: int
    active_count: int
    verified_count: int
    healthy_count: int
    items: list[IntegrationOverviewItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "active_count": self.active_count,
            "verified_count": self.verified_count,
            "healthy_count": self.healthy_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _health_state(
    *,
    status: str,
    verified: bool,
    warn_count: int,
    fail_count: int,
) -> str:
    normalized = (status or "").strip().lower()
    if fail_count > 0:
        return "failing"
    if warn_count > 0 or not verified:
        return "warning"
    if normalized == "active":
        return "healthy"
    return "inactive"


def build_integration_overview_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-overview",
) -> IntegrationOverviewView:
    records = list_integrations(registry)

    items: list[IntegrationOverviewItem] = []
    active_count = 0
    verified_count = 0
    healthy_count = 0

    for record in records:
        verification = verify_integration(
            registry,
            record.integration_id,
            strict=False,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        normalized_status = (record.status or "").strip().lower()
        if normalized_status == "active":
            active_count += 1
        if summary["verified"]:
            verified_count += 1

        health = _health_state(
            status=record.status,
            verified=summary["verified"],
            warn_count=summary["warn_count"],
            fail_count=summary["fail_count"],
        )
        if health == "healthy":
            healthy_count += 1

        items.append(
            IntegrationOverviewItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                version=record.version,
                verified=summary["verified"],
                health=health,
                command_ready=bool(getattr(record, "command_name", None)),
                install_ready=bool(getattr(record, "install_target", None)),
                endpoint_ready=bool(
                    getattr(record, "endpoint", None) or getattr(record, "base_url", None)
                ),
                metadata={
                    "requested_by": requested_by,
                    "checked_at": summary["checked_at"],
                    "pass_count": summary["pass_count"],
                    "warn_count": summary["warn_count"],
                    "fail_count": summary["fail_count"],
                },
            )
        )

    items.sort(
        key=lambda item: (
            0 if item.health == "failing"
            else 1 if item.health == "warning"
            else 2 if item.health == "healthy"
            else 3,
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationOverviewView(
        title="Integration Overview",
        total=len(items),
        active_count=active_count,
        verified_count=verified_count,
        healthy_count=healthy_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )