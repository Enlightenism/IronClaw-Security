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
class IntegrationHealthItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    verified: bool
    pass_count: int
    warn_count: int
    fail_count: int
    checked_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "verified": self.verified,
            "pass_count": self.pass_count,
            "warn_count": self.warn_count,
            "fail_count": self.fail_count,
            "checked_at": self.checked_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationHealthView:
    title: str
    total: int
    healthy_count: int
    warning_count: int
    failing_count: int
    items: list[IntegrationHealthItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "healthy_count": self.healthy_count,
            "warning_count": self.warning_count,
            "failing_count": self.failing_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_health_view(
    *,
    registry: IntegrationRegistry,
    strict: bool = False,
    requested_by: str = "ui-health",
) -> IntegrationHealthView:
    records = list_integrations(registry)

    items: list[IntegrationHealthItem] = []
    healthy_count = 0
    warning_count = 0
    failing_count = 0

    for record in records:
        result = verify_integration(
            registry,
            record.integration_id,
            strict=strict,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(result)

        pass_count = int(summary.get("pass_count", 0))
        warn_count = int(summary.get("warn_count", 0))
        fail_count = int(summary.get("fail_count", 0))
        verified = bool(summary.get("verified", fail_count == 0))
        checked_at = str(summary.get("checked_at", ""))

        if fail_count > 0:
            failing_count += 1
        elif warn_count > 0:
            warning_count += 1
        else:
            healthy_count += 1

        items.append(
            IntegrationHealthItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                verified=verified,
                pass_count=pass_count,
                warn_count=warn_count,
                fail_count=fail_count,
                checked_at=checked_at,
                metadata={
                    "strict": strict,
                    "requested_by": requested_by,
                },
            ),
        )

    items.sort(key=lambda item: (item.fail_count == 0, item.warn_count == 0, item.platform, item.slug))

    return IntegrationHealthView(
        title="Integration Health",
        total=len(items),
        healthy_count=healthy_count,
        warning_count=warning_count,
        failing_count=failing_count,
        items=items,
        metadata={
            "strict": strict,
            "requested_by": requested_by,
        },
    )
