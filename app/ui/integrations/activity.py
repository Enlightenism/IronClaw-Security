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
class IntegrationActivityEntry:
    integration_id: str
    slug: str
    platform: str
    activity_type: str
    summary: str
    occurred_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "platform": self.platform,
            "activity_type": self.activity_type,
            "summary": self.summary,
            "occurred_at": self.occurred_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationActivityView:
    title: str
    total: int
    items: list[IntegrationActivityEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_activity_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-activity",
) -> IntegrationActivityView:
    records = list_integrations(registry)
    items: list[IntegrationActivityEntry] = []

    for record in records:
        integration_type = getattr(record, "integration_type", "unknown")
        updated_at = str(getattr(record, "updated_at", ""))

        items.append(
            IntegrationActivityEntry(
                integration_id=record.integration_id,
                slug=record.slug,
                platform=record.platform,
                activity_type="registry",
                summary=f"{record.name} is registered with status '{record.status}'.",
                occurred_at=updated_at,
                metadata={
                    "version": record.version,
                    "integration_type": integration_type,
                },
            ),
        )

        verification = verify_integration(
            registry,
            record.integration_id,
            strict=False,
            requested_by=requested_by,
        )
        verification_summary = summarize_verification_result(verification)

        pass_count = int(verification_summary.get("pass_count", 0))
        warn_count = int(verification_summary.get("warn_count", 0))
        fail_count = int(verification_summary.get("fail_count", 0))
        checked_at = str(verification_summary.get("checked_at", updated_at))
        verified = bool(verification_summary.get("verified", fail_count == 0))
        verification_status = str(
            verification_summary.get(
                "status",
                "failed" if fail_count > 0 else "warning" if warn_count > 0 else "passed",
            ),
        )

        items.append(
            IntegrationActivityEntry(
                integration_id=record.integration_id,
                slug=record.slug,
                platform=record.platform,
                activity_type="verification",
                summary=(f"Verification completed with {pass_count} pass, {warn_count} warn, {fail_count} fail."),
                occurred_at=checked_at,
                metadata={
                    "verified": verified,
                    "status": verification_status,
                    "requested_by": requested_by,
                },
            ),
        )

        if getattr(record, "command_name", None):
            items.append(
                IntegrationActivityEntry(
                    integration_id=record.integration_id,
                    slug=record.slug,
                    platform=record.platform,
                    activity_type="installer",
                    summary=f"One-command installer is available as '{record.command_name}'.",
                    occurred_at=updated_at,
                    metadata={
                        "install_target": getattr(record, "install_target", None),
                        "one_command_ready": True,
                    },
                ),
            )

    items.sort(
        key=lambda item: (
            item.occurred_at,
            item.integration_id,
            item.activity_type,
        ),
        reverse=True,
    )

    return IntegrationActivityView(
        title="Integration Activity",
        total=len(items),
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
