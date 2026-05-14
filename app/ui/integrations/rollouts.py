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
class IntegrationRolloutItem:
    integration_id: str
    slug: str
    platform: str
    status: str
    rollout_state: str
    verification_ready: bool
    install_ready: bool
    pass_count: int
    warn_count: int
    fail_count: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "platform": self.platform,
            "status": self.status,
            "rollout_state": self.rollout_state,
            "verification_ready": self.verification_ready,
            "install_ready": self.install_ready,
            "pass_count": self.pass_count,
            "warn_count": self.warn_count,
            "fail_count": self.fail_count,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationRolloutsView:
    title: str
    total: int
    ready_count: int
    blocked_count: int
    items: list[IntegrationRolloutItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "ready_count": self.ready_count,
            "blocked_count": self.blocked_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _determine_rollout_state(
    *,
    status: str,
    verified: bool,
    fail_count: int,
    warn_count: int,
    install_ready: bool,
) -> str:
    if fail_count > 0 or not install_ready:
        return "blocked"
    if verified and status == "active":
        return "live"
    if verified and warn_count > 0:
        return "staged"
    if verified:
        return "ready"
    return "planned"


def build_integration_rollouts_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-rollouts",
) -> IntegrationRolloutsView:
    records = list_integrations(registry)

    items: list[IntegrationRolloutItem] = []
    ready_count = 0
    blocked_count = 0

    for record in records:
        verification = verify_integration(
            registry,
            record.integration_id,
            strict=True,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        install_ready = bool(record.command_name and record.install_target)
        rollout_state = _determine_rollout_state(
            status=record.status,
            verified=summary["verified"],
            fail_count=summary["fail_count"],
            warn_count=summary["warn_count"],
            install_ready=install_ready,
        )

        if rollout_state in {"ready", "staged", "live"}:
            ready_count += 1
        if rollout_state == "blocked":
            blocked_count += 1

        items.append(
            IntegrationRolloutItem(
                integration_id=record.integration_id,
                slug=record.slug,
                platform=record.platform,
                status=record.status,
                rollout_state=rollout_state,
                verification_ready=summary["verified"],
                install_ready=install_ready,
                pass_count=summary["pass_count"],
                warn_count=summary["warn_count"],
                fail_count=summary["fail_count"],
                metadata={
                    "requested_by": requested_by,
                    "command_name": record.command_name,
                    "install_target": record.install_target,
                },
            ),
        )

    items.sort(key=lambda item: (item.rollout_state, item.platform, item.slug))

    return IntegrationRolloutsView(
        title="Integration Rollouts",
        total=len(items),
        ready_count=ready_count,
        blocked_count=blocked_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
