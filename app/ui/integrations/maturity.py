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


def _normalize_status(value: str | None) -> str:
    if not value:
        return "unknown"
    return value.strip().lower()


def _lifecycle_stage(status: str) -> str:
    normalized = _normalize_status(status)
    if normalized in {"planned", "draft"}:
        return "planned"
    if normalized in {"active", "enabled"}:
        return "active"
    if normalized in {"disabled", "inactive"}:
        return "deprecated"
    if normalized in {"retired"}:
        return "retired"
    return "unknown"


def _maturity_score(
    *,
    lifecycle_stage: str,
    verified: bool,
    has_command: bool,
    has_install_target: bool,
    has_endpoint: bool,
    pass_count: int,
    warn_count: int,
    fail_count: int,
) -> int:
    score = 0

    # Lifecycle contribution.
    if lifecycle_stage == "active":
        score += 20
    elif lifecycle_stage == "planned":
        score += 10
    elif lifecycle_stage == "deprecated":
        score += 5

    # Capability / readiness.
    if verified:
        score += 25
    if has_command:
        score += 20
    if has_install_target:
        score += 15
    if has_endpoint:
        score += 10

    # Verification outcomes.
    score += min(pass_count * 1, 10)
    score -= min(warn_count * 2, 10)
    score -= min(fail_count * 10, 40)

    # Clamp between 0 and 100.
    return max(0, min(score, 100))


def _maturity_level(score: int) -> str:
    if score >= 80:
        return "optimized"
    if score >= 60:
        return "managed"
    if score >= 40:
        return "defined"
    if score >= 20:
        return "emerging"
    return "ad-hoc"


@dataclass(slots=True)
class IntegrationMaturityItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    lifecycle_stage: str
    maturity_score: int
    maturity_level: str
    verified: bool
    has_command: bool
    has_install_target: bool
    has_endpoint: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "lifecycle_stage": self.lifecycle_stage,
            "maturity_score": self.maturity_score,
            "maturity_level": self.maturity_level,
            "verified": self.verified,
            "has_command": self.has_command,
            "has_install_target": self.has_install_target,
            "has_endpoint": self.has_endpoint,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationMaturityView:
    title: str
    total: int
    optimized_count: int
    managed_count: int
    defined_count: int
    emerging_count: int
    ad_hoc_count: int
    items: list[IntegrationMaturityItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "optimized_count": self.optimized_count,
            "managed_count": self.managed_count,
            "defined_count": self.defined_count,
            "emerging_count": self.emerging_count,
            "ad_hoc_count": self.ad_hoc_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_maturity_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-maturity",
) -> IntegrationMaturityView:
    records = list_integrations(registry)

    items: list[IntegrationMaturityItem] = []
    optimized_count = 0
    managed_count = 0
    defined_count = 0
    emerging_count = 0
    ad_hoc_count = 0

    for record in records:
        status = getattr(record, "status", "unknown")
        lifecycle_stage = _lifecycle_stage(status)

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

        has_command = bool(getattr(record, "command_name", None))
        has_install_target = bool(getattr(record, "install_target", None))
        has_endpoint = bool(
            getattr(record, "endpoint", None) or getattr(record, "base_url", None),
        )

        score = _maturity_score(
            lifecycle_stage=lifecycle_stage,
            verified=verified,
            has_command=has_command,
            has_install_target=has_install_target,
            has_endpoint=has_endpoint,
            pass_count=pass_count,
            warn_count=warn_count,
            fail_count=fail_count,
        )
        level = _maturity_level(score)

        if level == "optimized":
            optimized_count += 1
        elif level == "managed":
            managed_count += 1
        elif level == "defined":
            defined_count += 1
        elif level == "emerging":
            emerging_count += 1
        else:
            ad_hoc_count += 1

        items.append(
            IntegrationMaturityItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=status,
                lifecycle_stage=lifecycle_stage,
                maturity_score=score,
                maturity_level=level,
                verified=verified,
                has_command=has_command,
                has_install_target=has_install_target,
                has_endpoint=has_endpoint,
                metadata={
                    "requested_by": requested_by,
                    "integration_type": getattr(record, "integration_type", "unknown"),
                    "pass_count": pass_count,
                    "warn_count": warn_count,
                    "fail_count": fail_count,
                },
            ),
        )

    items.sort(
        key=lambda item: (
            0 if item.maturity_level in {"ad-hoc", "emerging"} else 1 if item.maturity_level == "defined" else 2 if item.maturity_level == "managed" else 3,
            -item.maturity_score,
            item.platform,
            item.slug,
        ),
    )

    return IntegrationMaturityView(
        title="Integration Maturity",
        total=len(items),
        optimized_count=optimized_count,
        managed_count=managed_count,
        defined_count=defined_count,
        emerging_count=emerging_count,
        ad_hoc_count=ad_hoc_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
