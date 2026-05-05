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
class IntegrationControlItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    verified: bool
    strict_mode_enabled: bool
    command_control_enabled: bool
    install_control_enabled: bool
    endpoint_control_enabled: bool
    control_state: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "verified": self.verified,
            "strict_mode_enabled": self.strict_mode_enabled,
            "command_control_enabled": self.command_control_enabled,
            "install_control_enabled": self.install_control_enabled,
            "endpoint_control_enabled": self.endpoint_control_enabled,
            "control_state": self.control_state,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationControlsView:
    title: str
    total: int
    enforced_count: int
    partial_count: int
    missing_count: int
    items: list[IntegrationControlItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "enforced_count": self.enforced_count,
            "partial_count": self.partial_count,
            "missing_count": self.missing_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _control_state(
    *,
    verified: bool,
    strict_mode_enabled: bool,
    command_control_enabled: bool,
    install_control_enabled: bool,
    endpoint_control_enabled: bool,
) -> str:
    enabled_count = sum(
        [
            strict_mode_enabled,
            command_control_enabled,
            install_control_enabled,
            endpoint_control_enabled,
        ]
    )

    if verified and enabled_count == 4:
        return "enforced"
    if enabled_count >= 2:
        return "partial"
    return "missing"


def build_integration_controls_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-controls",
) -> IntegrationControlsView:
    records = list_integrations(registry)

    items: list[IntegrationControlItem] = []
    enforced_count = 0
    partial_count = 0
    missing_count = 0

    for record in records:
        verification = verify_integration(
            registry,
            record.integration_id,
            strict=True,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        command_control_enabled = bool(getattr(record, "command_name", None))
        install_control_enabled = bool(getattr(record, "install_target", None))
        endpoint_control_enabled = bool(
            getattr(record, "endpoint", None) or getattr(record, "base_url", None)
        )
        strict_mode_enabled = summary["verified"] and summary["fail_count"] == 0

        state = _control_state(
            verified=summary["verified"],
            strict_mode_enabled=strict_mode_enabled,
            command_control_enabled=command_control_enabled,
            install_control_enabled=install_control_enabled,
            endpoint_control_enabled=endpoint_control_enabled,
        )

        if state == "enforced":
            enforced_count += 1
        elif state == "partial":
            partial_count += 1
        else:
            missing_count += 1

        items.append(
            IntegrationControlItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=record.status,
                verified=summary["verified"],
                strict_mode_enabled=strict_mode_enabled,
                command_control_enabled=command_control_enabled,
                install_control_enabled=install_control_enabled,
                endpoint_control_enabled=endpoint_control_enabled,
                control_state=state,
                metadata={
                    "requested_by": requested_by,
                    "checked_at": summary["checked_at"],
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
            if item.control_state == "missing"
            else 1
            if item.control_state == "partial"
            else 2,
            item.platform,
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationControlsView(
        title="Integration Controls",
        total=len(items),
        enforced_count=enforced_count,
        partial_count=partial_count,
        missing_count=missing_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )