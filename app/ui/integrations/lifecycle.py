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
class IntegrationLifecycleItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    version: str
    integration_type: str
    phase: str
    verified: bool
    checked_at: str
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
            "phase": self.phase,
            "verified": self.verified,
            "checked_at": self.checked_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationLifecycleView:
    title: str
    total: int
    draft_count: int
    rollout_count: int
    live_count: int
    retired_count: int
    items: list[IntegrationLifecycleItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "draft_count": self.draft_count,
            "rollout_count": self.rollout_count,
            "live_count": self.live_count,
            "retired_count": self.retired_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _phase_for_record(
    *,
    status: str,
    verified: bool,
    command_ready: bool,
    install_ready: bool,
) -> str:
    normalized = (status or "").strip().lower()

    if normalized in {"disabled", "inactive", "retired"}:
        return "retired"
    if normalized in {"planned", "draft"}:
        return "draft"
    if normalized == "active" and verified and command_ready and install_ready:
        return "live"
    return "rollout"


def _phase_rank(phase: str) -> int:
    if phase == "draft":
        return 0
    if phase == "rollout":
        return 1
    if phase == "live":
        return 2
    if phase == "retired":
        return 3
    return 4


def build_integration_lifecycle_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-lifecycle",
) -> IntegrationLifecycleView:
    records = list_integrations(registry)

    items: list[IntegrationLifecycleItem] = []
    draft_count = 0
    rollout_count = 0
    live_count = 0
    retired_count = 0

    for record in records:
        verification = verify_integration(
            registry,
            record.integration_id,
            strict=False,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        verified = bool(summary.get("verified", False))
        checked_at = str(summary.get("checked_at", ""))
        pass_count = int(summary.get("pass_count", 0))
        warn_count = int(summary.get("warn_count", 0))
        fail_count = int(summary.get("fail_count", 0))

        phase = _phase_for_record(
            status=getattr(record, "status", ""),
            verified=verified,
            command_ready=bool(getattr(record, "command_name", None)),
            install_ready=bool(getattr(record, "install_target", None)),
        )

        if phase == "draft":
            draft_count += 1
        elif phase == "rollout":
            rollout_count += 1
        elif phase == "live":
            live_count += 1
        elif phase == "retired":
            retired_count += 1

        items.append(
            IntegrationLifecycleItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                version=record.version,
                integration_type=getattr(record, "integration_type", "unknown"),
                phase=phase,
                verified=verified,
                checked_at=checked_at,
                metadata={
                    "requested_by": requested_by,
                    "pass_count": pass_count,
                    "warn_count": warn_count,
                    "fail_count": fail_count,
                },
            )
        )

    items.sort(
        key=lambda item: (
            _phase_rank(item.phase),
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationLifecycleView(
        title="Integration Lifecycle",
        total=len(items),
        draft_count=draft_count,
        rollout_count=rollout_count,
        live_count=live_count,
        retired_count=retired_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )