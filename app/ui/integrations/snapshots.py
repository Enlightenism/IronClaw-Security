from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
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
class IntegrationSnapshotItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    version: str
    verified: bool
    snapshot_id: str
    created_at: str
    health: str
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
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at,
            "health": self.health,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationSnapshotsView:
    title: str
    total: int
    healthy_snapshot_count: int
    warning_snapshot_count: int
    failing_snapshot_count: int
    items: list[IntegrationSnapshotItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "healthy_snapshot_count": self.healthy_snapshot_count,
            "warning_snapshot_count": self.warning_snapshot_count,
            "failing_snapshot_count": self.failing_snapshot_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _snapshot_health(
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


def build_integration_snapshots_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-snapshots",
) -> IntegrationSnapshotsView:
    records = list_integrations(registry)

    items: list[IntegrationSnapshotItem] = []
    healthy_snapshot_count = 0
    warning_snapshot_count = 0
    failing_snapshot_count = 0

    generated_at = datetime.now(UTC)

    for record in records:
        verification = verify_integration(
            registry,
            record.integration_id,
            strict=False,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        health = _snapshot_health(
            status=record.status,
            verified=summary["verified"],
            warn_count=summary["warn_count"],
            fail_count=summary["fail_count"],
        )

        if health == "healthy":
            healthy_snapshot_count += 1
        elif health == "warning":
            warning_snapshot_count += 1
        elif health == "failing":
            failing_snapshot_count += 1

        created_at = summary.get("checked_at") or generated_at.isoformat()

        items.append(
            IntegrationSnapshotItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                version=record.version,
                verified=summary["verified"],
                snapshot_id=f"snapshot-{record.slug}-{record.version}",
                created_at=created_at,
                health=health,
                metadata={
                    "requested_by": requested_by,
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

    return IntegrationSnapshotsView(
        title="Integration Snapshots",
        total=len(items),
        healthy_snapshot_count=healthy_snapshot_count,
        warning_snapshot_count=warning_snapshot_count,
        failing_snapshot_count=failing_snapshot_count,
        items=items,
        metadata={
            "requested_by": requested_by,
            "generated_at": generated_at.isoformat(),
        },
    )