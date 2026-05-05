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
class IntegrationStatusItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    lifecycle_status: str
    verification_status: str
    verified: bool
    rollout_state: str
    command_ready: bool
    install_ready: bool
    checked_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "lifecycle_status": self.lifecycle_status,
            "verification_status": self.verification_status,
            "verified": self.verified,
            "rollout_state": self.rollout_state,
            "command_ready": self.command_ready,
            "install_ready": self.install_ready,
            "checked_at": self.checked_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationStatusView:
    title: str
    total: int
    live_count: int
    ready_count: int
    blocked_count: int
    items: list[IntegrationStatusItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "live_count": self.live_count,
            "ready_count": self.ready_count,
            "blocked_count": self.blocked_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _verification_status_from_summary(summary: dict[str, Any]) -> str:
    if summary["fail_count"] > 0:
        return "failed"
    if summary["warn_count"] > 0:
        return "warning"
    if summary["verified"]:
        return "passed"
    return "unknown"


def _determine_rollout_state(
    *,
    lifecycle_status: str,
    verified: bool,
    warn_count: int,
    fail_count: int,
    command_ready: bool,
    install_ready: bool,
) -> str:
    if fail_count > 0 or not command_ready:
        return "blocked"
    if verified and lifecycle_status == "active" and install_ready:
        return "live"
    if verified and warn_count > 0:
        return "staged"
    if verified:
        return "ready"
    return "planned"


def build_integration_status_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-status",
) -> IntegrationStatusView:
    records = list_integrations(registry)

    items: list[IntegrationStatusItem] = []
    live_count = 0
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

        command_ready = bool(getattr(record, "command_name", None))
        install_ready = bool(getattr(record, "install_target", None))

        rollout_state = _determine_rollout_state(
            lifecycle_status=record.status,
            verified=summary["verified"],
            warn_count=summary["warn_count"],
            fail_count=summary["fail_count"],
            command_ready=command_ready,
            install_ready=install_ready,
        )

        if rollout_state == "live":
            live_count += 1
        elif rollout_state in {"ready", "staged"}:
            ready_count += 1
        elif rollout_state == "blocked":
            blocked_count += 1

        items.append(
            IntegrationStatusItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                lifecycle_status=record.status,
                verification_status=_verification_status_from_summary(summary),
                verified=summary["verified"],
                rollout_state=rollout_state,
                command_ready=command_ready,
                install_ready=install_ready,
                checked_at=summary["checked_at"],
                metadata={
                    "requested_by": requested_by,
                    "pass_count": summary["pass_count"],
                    "warn_count": summary["warn_count"],
                    "fail_count": summary["fail_count"],
                    "verification_summary": summary,
                },
            )
        )

    items.sort(
        key=lambda item: (
            0
            if item.rollout_state == "blocked"
            else 1
            if item.rollout_state == "planned"
            else 2
            if item.rollout_state == "ready"
            else 3
            if item.rollout_state == "staged"
            else 4,
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationStatusView(
        title="Integration Status",
        total=len(items),
        live_count=live_count,
        ready_count=ready_count,
        blocked_count=blocked_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )