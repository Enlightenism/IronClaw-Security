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
class IntegrationSummaryItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    version: str
    integration_type: str
    verified: bool
    pass_count: int
    warn_count: int
    fail_count: int
    has_command: bool
    has_install_target: bool
    score: int
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
            "integration_type": self.integration_type,
            "verified": self.verified,
            "pass_count": self.pass_count,
            "warn_count": self.warn_count,
            "fail_count": self.fail_count,
            "has_command": self.has_command,
            "has_install_target": self.has_install_target,
            "score": self.score,
            "health": self.health,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationSummaryView:
    title: str
    total: int
    active_count: int
    verified_count: int
    healthy_count: int
    warning_count: int
    failing_count: int
    items: list[IntegrationSummaryItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "active_count": self.active_count,
            "verified_count": self.verified_count,
            "healthy_count": self.healthy_count,
            "warning_count": self.warning_count,
            "failing_count": self.failing_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _normalize_status(value: str | None) -> str:
    if not value:
        return "unknown"
    return value.strip().lower()


def _integration_health(
    *,
    status: str,
    verified: bool,
    warn_count: int,
    fail_count: int,
) -> str:
    if fail_count > 0:
        return "failing"
    if warn_count > 0 or not verified:
        return "warning"
    if status == "active":
        return "healthy"
    return "inactive"


def _integration_score(
    *,
    status: str,
    verified: bool,
    has_command: bool,
    has_install_target: bool,
    pass_count: int,
    warn_count: int,
    fail_count: int,
) -> int:
    score = 0

    if status == "active":
        score += 20
    elif status in {"planned", "draft"}:
        score += 10

    if verified:
        score += 30

    if has_command:
        score += 15
    if has_install_target:
        score += 15

    score += min(pass_count * 2, 20)
    score -= min(warn_count * 2, 10)
    score -= min(fail_count * 10, 30)

    return max(0, min(score, 100))


def build_integration_summary_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-summary",
) -> IntegrationSummaryView:
    records = list_integrations(registry)

    items: list[IntegrationSummaryItem] = []
    active_count = 0
    verified_count = 0
    healthy_count = 0
    warning_count = 0
    failing_count = 0

    for record in records:
        status = _normalize_status(getattr(record, "status", None))
        if status == "active":
            active_count += 1

        verification = verify_integration(
            registry,
            record.integration_id,
            strict=False,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        verified = bool(summary.get("verified", False))
        pass_count = int(summary.get("pass_count", 0))
        warn_count = int(summary.get("warn_count", 0))
        fail_count = int(summary.get("fail_count", 0))

        if verified:
            verified_count += 1

        has_command = bool(getattr(record, "command_name", None))
        has_install_target = bool(getattr(record, "install_target", None))

        health = _integration_health(
            status=status,
            verified=verified,
            warn_count=warn_count,
            fail_count=fail_count,
        )

        if health == "healthy":
            healthy_count += 1
        elif health == "warning":
            warning_count += 1
        elif health == "failing":
            failing_count += 1

        score = _integration_score(
            status=status,
            verified=verified,
            has_command=has_command,
            has_install_target=has_install_target,
            pass_count=pass_count,
            warn_count=warn_count,
            fail_count=fail_count,
        )

        items.append(
            IntegrationSummaryItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                version=record.version,
                integration_type=getattr(record, "integration_type", "unknown"),
                verified=verified,
                pass_count=pass_count,
                warn_count=warn_count,
                fail_count=fail_count,
                has_command=has_command,
                has_install_target=has_install_target,
                score=score,
                health=health,
                metadata={
                    "requested_by": requested_by,
                    "checked_at": summary.get("checked_at"),
                    "verification_summary": summary,
                },
            ),
        )

    items.sort(
        key=lambda item: (
            -item.score,
            item.platform,
            item.slug,
            item.integration_id,
        ),
    )

    return IntegrationSummaryView(
        title="Integration Summary",
        total=len(items),
        active_count=active_count,
        verified_count=verified_count,
        healthy_count=healthy_count,
        warning_count=warning_count,
        failing_count=failing_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
