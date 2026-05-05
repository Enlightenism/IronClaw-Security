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
class IntegrationReadinessItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    verified: bool
    command_ready: bool
    install_ready: bool
    endpoint_ready: bool
    pass_count: int
    warn_count: int
    fail_count: int
    readiness_score: int
    readiness_state: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "verified": self.verified,
            "command_ready": self.command_ready,
            "install_ready": self.install_ready,
            "endpoint_ready": self.endpoint_ready,
            "pass_count": self.pass_count,
            "warn_count": self.warn_count,
            "fail_count": self.fail_count,
            "readiness_score": self.readiness_score,
            "readiness_state": self.readiness_state,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationReadinessView:
    title: str
    total: int
    ready_count: int
    nearly_ready_count: int
    blocked_count: int
    items: list[IntegrationReadinessItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "ready_count": self.ready_count,
            "nearly_ready_count": self.nearly_ready_count,
            "blocked_count": self.blocked_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _readiness_score(
    *,
    status: str,
    verified: bool,
    command_ready: bool,
    install_ready: bool,
    endpoint_ready: bool,
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
        score += 25
    if command_ready:
        score += 15
    if install_ready:
        score += 15
    if endpoint_ready:
        score += 10

    score += min(pass_count * 2, 20)
    score -= min(warn_count * 2, 10)
    score -= min(fail_count * 15, 45)

    return max(0, min(score, 100))


def _readiness_state(
    *,
    score: int,
    fail_count: int,
) -> str:
    if fail_count > 0 or score < 45:
        return "blocked"
    if score < 75:
        return "nearly-ready"
    return "ready"


def build_integration_readiness_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-readiness",
) -> IntegrationReadinessView:
    records = list_integrations(registry)

    items: list[IntegrationReadinessItem] = []
    ready_count = 0
    nearly_ready_count = 0
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
        endpoint_ready = bool(
            getattr(record, "endpoint", None) or getattr(record, "base_url", None)
        )

        score = _readiness_score(
            status=record.status,
            verified=summary["verified"],
            command_ready=command_ready,
            install_ready=install_ready,
            endpoint_ready=endpoint_ready,
            pass_count=summary["pass_count"],
            warn_count=summary["warn_count"],
            fail_count=summary["fail_count"],
        )
        state = _readiness_state(
            score=score,
            fail_count=summary["fail_count"],
        )

        if state == "ready":
            ready_count += 1
        elif state == "nearly-ready":
            nearly_ready_count += 1
        else:
            blocked_count += 1

        items.append(
            IntegrationReadinessItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                verified=summary["verified"],
                command_ready=command_ready,
                install_ready=install_ready,
                endpoint_ready=endpoint_ready,
                pass_count=summary["pass_count"],
                warn_count=summary["warn_count"],
                fail_count=summary["fail_count"],
                readiness_score=score,
                readiness_state=state,
                metadata={
                    "requested_by": requested_by,
                    "checked_at": summary["checked_at"],
                },
            )
        )

    items.sort(
        key=lambda item: (
            0 if item.readiness_state == "blocked"
            else 1 if item.readiness_state == "nearly-ready"
            else 2,
            -item.readiness_score,
            item.platform,
            item.slug,
        )
    )

    return IntegrationReadinessView(
        title="Integration Readiness",
        total=len(items),
        ready_count=ready_count,
        nearly_ready_count=nearly_ready_count,
        blocked_count=blocked_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )