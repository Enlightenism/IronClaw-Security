from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.adapters.base import BaseIntegrationAdapter
from app.adapters.generic_agent_adapter import GenericAgentAdapter
from app.adapters.mcp_tool_adapter import McpToolAdapter
from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
    list_integrations,
)
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)


@dataclass(slots=True)
class IntegrationCoverageItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    protocol_version: str
    capability_count: int
    supported_action_type_count: int
    verification_pass_count: int
    verification_warn_count: int
    verification_fail_count: int
    coverage_score: int
    coverage_tier: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "protocol_version": self.protocol_version,
            "capability_count": self.capability_count,
            "supported_action_type_count": self.supported_action_type_count,
            "verification_pass_count": self.verification_pass_count,
            "verification_warn_count": self.verification_warn_count,
            "verification_fail_count": self.verification_fail_count,
            "coverage_score": self.coverage_score,
            "coverage_tier": self.coverage_tier,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationCoverageView:
    title: str
    total: int
    strong_count: int
    moderate_count: int
    weak_count: int
    items: list[IntegrationCoverageItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "strong_count": self.strong_count,
            "moderate_count": self.moderate_count,
            "weak_count": self.weak_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _build_adapter_for_integration(
    integration_id: str,
    *,
    registry: IntegrationRegistry,
) -> BaseIntegrationAdapter | None:
    record = get_integration(registry, integration_id)
    if record is None:
        return None

    if record.slug == "generic-agent":
        return GenericAgentAdapter(record=record)
    if record.slug == "openclaw":
        return McpToolAdapter(record=record)
    if record.slug == "claude-code":
        return GenericAgentAdapter(record=record, runtime="claude-code")

    return BaseIntegrationAdapter(record=record)


def _coverage_score(
    *,
    capability_count: int,
    supported_action_type_count: int,
    verification_pass_count: int,
    verification_warn_count: int,
    verification_fail_count: int,
) -> int:
    score = 0
    score += min(capability_count * 10, 40)
    score += min(supported_action_type_count * 10, 20)
    score += min(verification_pass_count * 5, 30)
    score -= min(verification_warn_count * 5, 10)
    score -= min(verification_fail_count * 15, 45)
    return max(0, min(score, 100))


def _coverage_tier(score: int) -> str:
    if score >= 75:
        return "strong"
    if score >= 45:
        return "moderate"
    return "weak"


def build_integration_coverage_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-coverage",
) -> IntegrationCoverageView:
    records = list_integrations(registry)

    items: list[IntegrationCoverageItem] = []
    strong_count = 0
    moderate_count = 0
    weak_count = 0

    for record in records:
        adapter = _build_adapter_for_integration(
            record.integration_id,
            registry=registry,
        )
        if adapter is None:
            continue

        handshake = adapter.handshake()
        capability_count = len(handshake.capabilities)

        supported_action_type_count = 0
        if hasattr(adapter, "supported_action_types"):
            supported_action_type_count = len(adapter.supported_action_types())  # type: ignore[attr-defined]

        verification = verify_integration(
            registry,
            record.integration_id,
            strict=False,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        score = _coverage_score(
            capability_count=capability_count,
            supported_action_type_count=supported_action_type_count,
            verification_pass_count=summary["pass_count"],
            verification_warn_count=summary["warn_count"],
            verification_fail_count=summary["fail_count"],
        )
        tier = _coverage_tier(score)

        if tier == "strong":
            strong_count += 1
        elif tier == "moderate":
            moderate_count += 1
        else:
            weak_count += 1

        items.append(
            IntegrationCoverageItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                protocol_version=adapter.protocol_version,
                capability_count=capability_count,
                supported_action_type_count=supported_action_type_count,
                verification_pass_count=summary["pass_count"],
                verification_warn_count=summary["warn_count"],
                verification_fail_count=summary["fail_count"],
                coverage_score=score,
                coverage_tier=tier,
                metadata={
                    "requested_by": requested_by,
                },
            )
        )

    items.sort(
        key=lambda item: (
            0 if item.coverage_tier == "weak" else 1 if item.coverage_tier == "moderate" else 2,
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationCoverageView(
        title="Integration Coverage",
        total=len(items),
        strong_count=strong_count,
        moderate_count=moderate_count,
        weak_count=weak_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )