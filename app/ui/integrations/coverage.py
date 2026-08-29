from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.adapters.base import BaseIntegrationAdapter
from app.adapters.generic_agent_adapter import GenericAgentAdapter
from app.adapters.mcp_tool_adapter import McpToolAdapter
from app.core.install_key_formats import (
    get_install_key_format_spec,
    normalize_install_key_program,
)
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
    install_key_program: str | None = None
    install_key_family: str | None = None
    install_key_prefix: str | None = None
    install_key_aliases: list[str] = field(default_factory=list)
    shared_install_key_family: bool = False
    available: bool = False
    rollout_status: str = "planned"
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
            "install_key_program": self.install_key_program,
            "install_key_family": self.install_key_family,
            "install_key_prefix": self.install_key_prefix,
            "install_key_aliases": list(self.install_key_aliases),
            "shared_install_key_family": self.shared_install_key_family,
            "available": self.available,
            "rollout_status": self.rollout_status,
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


def _resolve_install_key_metadata(record: Any) -> dict[str, Any]:
    candidates = [
        getattr(record, "platform", None),
        getattr(record, "slug", None),
        (getattr(record, "metadata", {}) or {}).get("runtime"),
        (getattr(record, "metadata", {}) or {}).get("install_key_program"),
        (getattr(record, "metadata", {}) or {}).get("platform"),
    ]

    for candidate in candidates:
        normalized = normalize_install_key_program(candidate)
        if normalized is None:
            continue
        spec = get_install_key_format_spec(normalized)
        return {
            "install_key_program": spec.program,
            "install_key_family": spec.family,
            "install_key_prefix": spec.prefix,
            "install_key_aliases": list(spec.platform_aliases),
            "shared_install_key_family": len(spec.platform_aliases) > 1 or spec.program == "security_guardian",
        }

    return {
        "install_key_program": None,
        "install_key_family": None,
        "install_key_prefix": None,
        "install_key_aliases": [],
        "shared_install_key_family": False,
    }


def _rollout_status_for_record(record: Any, install_key_program: str | None) -> str:
    status = str(getattr(record, "status", "") or "").strip().lower()
    if status == "active" and install_key_program:
        return "available"
    if status == "disabled":
        return "disabled"
    if status == "deprecated":
        return "deprecated"
    if install_key_program:
        return "planned"
    return "not_applicable"


def _coverage_score(
    *,
    capability_count: int,
    supported_action_type_count: int,
    verification_pass_count: int,
    verification_warn_count: int,
    verification_fail_count: int,
    install_key_program: str | None = None,
    available: bool = False,
) -> int:
    score = 0
    score += min(capability_count * 10, 40)
    score += min(supported_action_type_count * 10, 20)
    score += min(verification_pass_count * 5, 30)
    score -= min(verification_warn_count * 5, 10)
    score -= min(verification_fail_count * 15, 45)
    if install_key_program:
        score += 10
    if available:
        score += 5
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
        install_key_metadata = _resolve_install_key_metadata(record)
        install_key_program = install_key_metadata["install_key_program"]
        available = bool(install_key_program) and str(getattr(record, "status", "") or "").strip().lower() == "active"
        rollout_status = _rollout_status_for_record(record, install_key_program)

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
            install_key_program=install_key_program,
            available=available,
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
                install_key_program=install_key_program,
                install_key_family=install_key_metadata["install_key_family"],
                install_key_prefix=install_key_metadata["install_key_prefix"],
                install_key_aliases=install_key_metadata["install_key_aliases"],
                shared_install_key_family=install_key_metadata["shared_install_key_family"],
                available=available,
                rollout_status=rollout_status,
                metadata={
                    "requested_by": requested_by,
                    "install_key_status": rollout_status,
                    "availability_message": ("Install key is active for this runtime family." if available else "Install key rollout is not active for this runtime family."),
                },
            ),
        )

    items.sort(
        key=lambda item: (
            0 if item.coverage_tier == "weak" else 1 if item.coverage_tier == "moderate" else 2,
            item.platform,
            item.slug,
            item.integration_id,
        ),
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
