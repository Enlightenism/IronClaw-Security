from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

CapabilitySupport = Literal["native", "partial", "unsupported"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PlatformCapability:
    name: str
    support: CapabilitySupport
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "support": self.support,
            "details": self.details,
        }


@dataclass(slots=True)
class PlatformProfile:
    platform: str
    display_name: str
    install_mode: str
    capabilities: list[PlatformCapability] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "display_name": self.display_name,
            "install_mode": self.install_mode,
            "capabilities": [capability.to_dict() for capability in self.capabilities],
            "metadata": dict(self.metadata),
            "checked_at": self.checked_at,
        }


def default_platform_profiles() -> list[PlatformProfile]:
    return [
        PlatformProfile(
            platform="claude-code",
            display_name="Claude Code",
            install_mode="one-command-local",
            capabilities=[
                PlatformCapability("prompt_interception", "native", "Supports local interception workflows."),
                PlatformCapability("tool_interception", "native", "Supports guarded tool execution flows."),
                PlatformCapability(
                    "execution_interception",
                    "partial",
                    "Execution plan interception depends on runtime hook depth.",
                ),
                PlatformCapability("review_queue", "partial", "Review queue can be layered through IronClaw."),
                PlatformCapability("telemetry", "native", "Telemetry can be forwarded to IronClaw."),
            ],
            metadata={
                "adapter": "app.adapters.claude_code_adapter",
                "priority": 1,
            },
        ),
        PlatformProfile(
            platform="openclaw",
            display_name="OpenClaw",
            install_mode="one-command-local",
            capabilities=[
                PlatformCapability("prompt_interception", "native", "Builder prompt paths can be guarded."),
                PlatformCapability("tool_interception", "native", "Tool chains can be gated before execution."),
                PlatformCapability("execution_interception", "native", "Workflow execution plans can be guarded."),
                PlatformCapability("review_queue", "native", "Review holds can be routed through IronClaw."),
                PlatformCapability("telemetry", "native", "Execution telemetry can be aggregated."),
            ],
            metadata={
                "adapter": "app.adapters.openclaw_adapter",
                "priority": 2,
            },
        ),
        PlatformProfile(
            platform="generic-agent",
            display_name="Generic Agent Runtime",
            install_mode="api-attachment",
            capabilities=[
                PlatformCapability("prompt_interception", "partial", "Requires host runtime hook support."),
                PlatformCapability("tool_interception", "partial", "Requires wrapper-based interception."),
                PlatformCapability("execution_interception", "partial", "Depends on host execution contract."),
                PlatformCapability("review_queue", "partial", "Can be attached via IronClaw policy responses."),
                PlatformCapability("telemetry", "native", "Telemetry can be sent through API contracts."),
            ],
            metadata={
                "adapter": "app.adapters.generic_agent_adapter",
                "priority": 3,
            },
        ),
    ]


def list_platform_profiles() -> list[PlatformProfile]:
    return sorted(
        default_platform_profiles(),
        key=lambda item: (item.metadata.get("priority", 999), item.platform),
    )


def get_platform_profile(platform: str) -> PlatformProfile | None:
    normalized = platform.strip().lower()
    for profile in default_platform_profiles():
        if profile.platform == normalized:
            return profile
    return None


def summarize_platform_profile(profile: PlatformProfile) -> dict[str, Any]:
    support_counts = {"native": 0, "partial": 0, "unsupported": 0}
    for capability in profile.capabilities:
        support_counts[capability.support] = support_counts.get(capability.support, 0) + 1

    return {
        "platform": profile.platform,
        "display_name": profile.display_name,
        "install_mode": profile.install_mode,
        "capability_count": len(profile.capabilities),
        "native_capabilities": support_counts["native"],
        "partial_capabilities": support_counts["partial"],
        "unsupported_capabilities": support_counts["unsupported"],
        "checked_at": profile.checked_at,
    }
