from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

IntegrationStatus = Literal["planned", "active", "disabled", "deprecated"]
IntegrationType = Literal["native", "adapter", "cli", "remote"]
CapabilityName = Literal[
    "prompt_interception",
    "tool_interception",
    "execution_interception",
    "file_guard",
    "shell_guard",
    "network_guard",
    "git_guard",
    "review_queue",
    "audit_export",
    "policy_sync",
    "telemetry",
    "groq_assist",
]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class IntegrationCapability:
    name: CapabilityName
    enabled: bool = True
    details: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "details": self.details,
        }


@dataclass(slots=True)
class IntegrationRecord:
    integration_id: str
    name: str
    slug: str
    platform: str
    integration_type: IntegrationType
    status: IntegrationStatus = "planned"
    version: str = "0.1.0"
    command_name: str | None = None
    description: str = ""
    entrypoint: str | None = None
    install_target: str | None = None
    capabilities: list[IntegrationCapability] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "name": self.name,
            "slug": self.slug,
            "platform": self.platform,
            "integration_type": self.integration_type,
            "status": self.status,
            "version": self.version,
            "command_name": self.command_name,
            "description": self.description,
            "entrypoint": self.entrypoint,
            "install_target": self.install_target,
            "capabilities": [capability.to_dict() for capability in self.capabilities],
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(slots=True)
class IntegrationRegistry:
    items: dict[str, IntegrationRecord] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        records = sorted(self.items.values(), key=lambda item: (item.platform, item.name, item.integration_id))
        return {
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "total": len(records),
            "items": [record.to_dict() for record in records],
        }


def initialize_integration_registry() -> IntegrationRegistry:
    registry = IntegrationRegistry()
    for record in default_integrations():
        register_integration(registry, record)
    return registry


def default_integrations() -> list[IntegrationRecord]:
    return [
        IntegrationRecord(
            integration_id="integration-claude-code",
            name="Claude Code Adapter",
            slug="claude-code",
            platform="claude-code",
            integration_type="adapter",
            status="planned",
            version="0.1.0",
            command_name="ironclaw install claude-code",
            description="One-command IronClaw protection layer for Claude Code style local agent workflows.",
            entrypoint="app.adapters.claude_code_adapter",
            install_target="local",
            capabilities=[
                IntegrationCapability("prompt_interception", True, "Guard user and system prompt flows."),
                IntegrationCapability("tool_interception", True, "Guard tool invocations before execution."),
                IntegrationCapability("execution_interception", True, "Evaluate execution plans and outcomes."),
                IntegrationCapability("review_queue", True, "Hold risky actions for review."),
                IntegrationCapability("telemetry", True, "Publish integration telemetry events."),
                IntegrationCapability("groq_assist", True, "Optional Groq second-opinion security reasoning."),
            ],
            metadata={
                "priority": 1,
                "one_command_install": True,
                "supports_local_runtime": True,
            },
        ),
        IntegrationRecord(
            integration_id="integration-openclaw",
            name="OpenClaw Adapter",
            slug="openclaw",
            platform="openclaw",
            integration_type="adapter",
            status="planned",
            version="0.1.0",
            command_name="ironclaw install openclaw",
            description="Adapter layer for OpenClaw-style builder and agent runtimes.",
            entrypoint="app.adapters.openclaw_adapter",
            install_target="local",
            capabilities=[
                IntegrationCapability("prompt_interception", True),
                IntegrationCapability("tool_interception", True),
                IntegrationCapability("execution_interception", True),
                IntegrationCapability("file_guard", True),
                IntegrationCapability("network_guard", True),
                IntegrationCapability("policy_sync", True),
                IntegrationCapability("telemetry", True),
            ],
            metadata={
                "priority": 2,
                "one_command_install": True,
                "supports_builder_mode": True,
            },
        ),
        IntegrationRecord(
            integration_id="integration-generic-agent",
            name="Generic Agent Adapter",
            slug="generic-agent",
            platform="generic",
            integration_type="native",
            status="planned",
            version="0.1.0",
            command_name="ironclaw install generic-agent",
            description="Generic integration profile for AI runtimes that can call IronClaw over local APIs.",
            entrypoint="app.adapters.generic_agent_adapter",
            install_target="local",
            capabilities=[
                IntegrationCapability("prompt_interception", True),
                IntegrationCapability("tool_interception", True),
                IntegrationCapability("execution_interception", True),
                IntegrationCapability("audit_export", True),
                IntegrationCapability("telemetry", True),
            ],
            metadata={
                "priority": 3,
                "one_command_install": True,
                "transport": "http",
            },
        ),
        IntegrationRecord(
            integration_id="integration-llamafirewall",
            name="LlamaFirewall Adapter",
            slug="llamafirewall",
            platform="llamafirewall",
            integration_type="adapter",
            status="planned",
            version="0.1.0",
            command_name="ironclaw install llamafirewall",
            description=("IronClaw adapter for Meta's LlamaFirewall open-source guardrail system. " "Guards prompt submissions, tool calls, and agent actions through the IronClaw " "policy engine before dispatching to LlamaFirewall's PromptGuard 2 and " "agent alignment scanning layers."),
            entrypoint="app.adapters.llamafirewall_adapter",
            install_target="local",
            capabilities=[
                IntegrationCapability("prompt_interception", True, "Intercept and evaluate prompts before LlamaFirewall scanning."),
                IntegrationCapability("tool_interception", True, "Guard tool calls and agent actions before dispatch."),
                IntegrationCapability("execution_interception", True, "Evaluate agent execution plans prior to LlamaFirewall."),
                IntegrationCapability("review_queue", True, "Hold flagged prompts and tool calls for human review."),
                IntegrationCapability("audit_export", True, "Export LlamaFirewall scan decisions to the audit log."),
                IntegrationCapability("telemetry", True, "Publish LlamaFirewall integration telemetry events."),
            ],
            metadata={
                "priority": 4,
                "one_command_install": True,
                "supports_local_runtime": True,
                "scanner_layers": ["PromptGuard2", "AgentAlignmentCheck", "CodeShield"],
                "vendor": "Meta",
                "framework": "PurpleLlama",
            },
        ),
        IntegrationRecord(
            integration_id="integration-cape",
            name="CAPE Sandbox Adapter",
            slug="cape",
            platform="cape",
            integration_type="adapter",
            status="planned",
            version="0.1.0",
            command_name="ironclaw install cape",
            description=("IronClaw adapter for the CAPE malware analysis sandbox. " "Guards sample, URL, and process submissions through the IronClaw " "policy engine before dispatching to the CAPE analysis API."),
            entrypoint="app.adapters.cape_adapter",
            install_target="local",
            capabilities=[
                IntegrationCapability("execution_interception", True, "Gate sandbox task submissions before dispatch to CAPE."),
                IntegrationCapability("file_guard", True, "Evaluate sample files before CAPE analysis."),
                IntegrationCapability("network_guard", True, "Guard URL submissions to CAPE sandbox."),
                IntegrationCapability("review_queue", True, "Hold policy-violating submissions for human review."),
                IntegrationCapability("audit_export", True, "Export CAPE sandbox decisions to the audit log."),
                IntegrationCapability("telemetry", True, "Publish CAPE integration telemetry events."),
            ],
            metadata={
                "priority": 5,
                "one_command_install": True,
                "supports_local_runtime": False,
                "runtime": "cape",
                "analysis_mode": "sandbox-guard",
            },
        ),
    ]


def register_integration(
    registry: IntegrationRegistry,
    record: IntegrationRecord,
) -> IntegrationRegistry:
    if not record.integration_id.strip():
        raise ValueError("integration_id is required")
    if not record.slug.strip():
        raise ValueError("slug is required")
    if not record.name.strip():
        raise ValueError("name is required")
    if record.integration_id in registry.items:
        raise ValueError(f"integration already registered: {record.integration_id}")

    now = _utc_now()
    record.created_at = record.created_at or now
    record.updated_at = now
    registry.items[record.integration_id] = record
    registry.updated_at = now
    return registry


def get_integration(
    registry: IntegrationRegistry,
    integration_id: str,
) -> IntegrationRecord | None:
    return registry.items.get(integration_id)


def list_integrations(
    registry: IntegrationRegistry,
    *,
    status: IntegrationStatus | None = None,
    platform: str | None = None,
    capability: CapabilityName | None = None,
) -> list[IntegrationRecord]:
    records = list(registry.items.values())

    if status is not None:
        records = [record for record in records if record.status == status]

    if platform is not None:
        normalized_platform = platform.strip().lower()
        records = [record for record in records if record.platform.strip().lower() == normalized_platform]

    if capability is not None:
        records = [record for record in records if any(item.name == capability and item.enabled for item in record.capabilities)]

    return sorted(records, key=lambda item: (item.platform, item.name, item.integration_id))


def update_integration_status(
    registry: IntegrationRegistry,
    integration_id: str,
    status: IntegrationStatus,
) -> IntegrationRecord:
    record = registry.items.get(integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    now = _utc_now()
    record.status = status
    record.updated_at = now
    registry.updated_at = now
    return record


def summarize_integration_registry(registry: IntegrationRegistry) -> dict[str, Any]:
    records = list_integrations(registry)

    by_status: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    capability_counts: dict[str, int] = {}

    for record in records:
        by_status[record.status] = by_status.get(record.status, 0) + 1
        by_platform[record.platform] = by_platform.get(record.platform, 0) + 1

        for capability in record.capabilities:
            if capability.enabled:
                capability_counts[capability.name] = capability_counts.get(capability.name, 0) + 1

    return {
        "created_at": registry.created_at,
        "updated_at": registry.updated_at,
        "total_integrations": len(records),
        "active_integrations": by_status.get("active", 0),
        "planned_integrations": by_status.get("planned", 0),
        "disabled_integrations": by_status.get("disabled", 0),
        "deprecated_integrations": by_status.get("deprecated", 0),
        "platforms": by_platform,
        "capabilities": capability_counts,
        "one_command_ready_targets": [record.slug for record in records if record.command_name],
    }
