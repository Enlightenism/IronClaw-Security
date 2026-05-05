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


def _clean_text(value: Any, *, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _safe_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _record_status(record: Any) -> str:
    return _clean_text(getattr(record, "status", None), default="unknown").lower()


def _record_platform(record: Any) -> str:
    return _clean_text(getattr(record, "platform", None), default="unknown")


def _record_slug(record: Any) -> str:
    return _clean_text(getattr(record, "slug", None), default="unknown")


def _record_name(record: Any) -> str:
    return _clean_text(getattr(record, "name", None), default="Unnamed Integration")


def _record_id(record: Any) -> str:
    return _clean_text(getattr(record, "integration_id", None), default="unknown")


@dataclass(slots=True)
class IntegrationGovernanceItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    verified: bool
    lifecycle_state: str
    control_state: str
    governance_score: int
    governance_state: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "verified": self.verified,
            "lifecycle_state": self.lifecycle_state,
            "control_state": self.control_state,
            "governance_score": self.governance_score,
            "governance_state": self.governance_state,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationGovernanceView:
    title: str
    total: int
    governed_count: int
    partial_count: int
    at_risk_count: int
    verified_count: int
    enforced_count: int
    items: list[IntegrationGovernanceItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "governed_count": self.governed_count,
            "partial_count": self.partial_count,
            "at_risk_count": self.at_risk_count,
            "verified_count": self.verified_count,
            "enforced_count": self.enforced_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _lifecycle_state(status: str) -> str:
    normalized = _clean_text(status, default="unknown").lower()
    if normalized in {"planned", "draft", "review"}:
        return "draft"
    if normalized in {"disabled", "inactive", "retired", "archived"}:
        return "retired"
    if normalized in {"unknown"}:
        return "unknown"
    return "active"


def _control_state(
    *,
    verified: bool,
    command_ready: bool,
    install_ready: bool,
    endpoint_ready: bool,
    fail_count: int,
) -> str:
    if fail_count > 0:
        return "at-risk"

    enabled_count = sum(
        (
            verified,
            command_ready,
            install_ready,
            endpoint_ready,
        )
    )
    if enabled_count >= 4:
        return "enforced"
    if enabled_count >= 2:
        return "partial"
    return "minimal"


def _governance_score(
    *,
    lifecycle_state: str,
    verified: bool,
    command_ready: bool,
    install_ready: bool,
    endpoint_ready: bool,
    warn_count: int,
    fail_count: int,
) -> int:
    score = 0

    if lifecycle_state == "active":
        score += 20
    elif lifecycle_state == "draft":
        score += 10

    if verified:
        score += 30
    if command_ready:
        score += 15
    if install_ready:
        score += 15
    if endpoint_ready:
        score += 10

    score -= min(warn_count * 3, 15)
    score -= min(fail_count * 20, 60)

    return max(0, min(score, 100))


def _governance_state(score: int) -> str:
    if score >= 75:
        return "governed"
    if score >= 45:
        return "partial"
    return "at-risk"


def build_integration_governance_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-governance",
) -> IntegrationGovernanceView:
    records = list_integrations(registry)

    items: list[IntegrationGovernanceItem] = []
    governed_count = 0
    partial_count = 0
    at_risk_count = 0
    verified_count = 0
    enforced_count = 0

    for record in records:
        integration_id = _record_id(record)

        verification = verify_integration(
            registry,
            integration_id,
            strict=True,
            requested_by=requested_by,
        )
        summary = dict(summarize_verification_result(verification) or {})

        verified = bool(summary.get("verified", False))
        checked_at = _clean_text(summary.get("checked_at"))
        pass_count = _safe_int(summary.get("pass_count", 0))
        warn_count = _safe_int(summary.get("warn_count", 0))
        fail_count = _safe_int(summary.get("fail_count", 0))

        status = _record_status(record)
        lifecycle_state = _lifecycle_state(status)
        command_ready = bool(getattr(record, "command_name", None))
        install_ready = bool(getattr(record, "install_target", None))
        endpoint_ready = bool(
            getattr(record, "endpoint", None) or getattr(record, "base_url", None)
        )

        control_state = _control_state(
            verified=verified,
            command_ready=command_ready,
            install_ready=install_ready,
            endpoint_ready=endpoint_ready,
            fail_count=fail_count,
        )

        score = _governance_score(
            lifecycle_state=lifecycle_state,
            verified=verified,
            command_ready=command_ready,
            install_ready=install_ready,
            endpoint_ready=endpoint_ready,
            warn_count=warn_count,
            fail_count=fail_count,
        )
        state = _governance_state(score)

        if verified:
            verified_count += 1
        if control_state == "enforced":
            enforced_count += 1

        if state == "governed":
            governed_count += 1
        elif state == "partial":
            partial_count += 1
        else:
            at_risk_count += 1

        items.append(
            IntegrationGovernanceItem(
                integration_id=integration_id,
                slug=_record_slug(record),
                name=_record_name(record),
                platform=_record_platform(record),
                status=status,
                verified=verified,
                lifecycle_state=lifecycle_state,
                control_state=control_state,
                governance_score=score,
                governance_state=state,
                metadata={
                    "requested_by": requested_by,
                    "checked_at": checked_at,
                    "pass_count": pass_count,
                    "warn_count": warn_count,
                    "fail_count": fail_count,
                    "verification_summary": summary,
                },
            )
        )

    items.sort(
        key=lambda item: (
            0
            if item.governance_state == "at-risk"
            else 1
            if item.governance_state == "partial"
            else 2,
            -item.governance_score,
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationGovernanceView(
        title="Integration Governance",
        total=len(items),
        governed_count=governed_count,
        partial_count=partial_count,
        at_risk_count=at_risk_count,
        verified_count=verified_count,
        enforced_count=enforced_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )