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
                PlatformCapability("prompt_interception", "native", "Local prompt hooks can inspect and block policy-unsafe prompts."),
                PlatformCapability("tool_interception", "native", "Tool invocations can be intercepted before execution."),
                PlatformCapability("execution_interception", "native", "Execution plans can be evaluated before command dispatch."),
                PlatformCapability("shell_guard", "native", "Shell and subprocess execution can be gated through IronClaw."),
                PlatformCapability("file_guard", "native", "Workspace file reads, edits, and writes can be protected."),
                PlatformCapability("network_guard", "partial", "Outbound networking is governed by host-level controls and policy hooks."),
                PlatformCapability("review_queue", "native", "Risky actions can be queued for approval or human review."),
                PlatformCapability("telemetry", "native", "Telemetry can be forwarded to the IronClaw control plane."),
                PlatformCapability("policy_sync", "native", "Policy bundles can be synchronized to the runtime agent."),
                PlatformCapability("audit_export", "native", "Guard decisions and event streams can be exported to audit records."),
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
                PlatformCapability("prompt_interception", "native", "Builder prompt paths can be guarded before execution."),
                PlatformCapability("tool_interception", "native", "Tool chains can be gated before execution."),
                PlatformCapability("execution_interception", "native", "Workflow execution plans can be guarded end-to-end."),
                PlatformCapability("shell_guard", "native", "Command shells and subprocess execution are governed by policy."),
                PlatformCapability("file_guard", "native", "File operations can be reviewed before read or write actions."),
                PlatformCapability("network_guard", "native", "Network and remote call paths can be monitored and restricted."),
                PlatformCapability("review_queue", "native", "Review holdings can be routed to approval workflows."),
                PlatformCapability("telemetry", "native", "Execution telemetry can be aggregated and correlated."),
                PlatformCapability("policy_sync", "native", "Policies can be synced and enforced from the runtime control plane."),
                PlatformCapability("audit_export", "native", "Audit logs can be exported for incident review and governance."),
            ],
            metadata={
                "adapter": "app.adapters.openclaw_adapter",
                "priority": 2,
            },
        ),
        PlatformProfile(
            platform="cursor",
            display_name="Cursor",
            install_mode="one-command-local",
            capabilities=[
                PlatformCapability("prompt_interception", "native", "Cursor prompt payloads can be intercepted and evaluated before dispatch."),
                PlatformCapability("tool_interception", "native", "Workspace tooling hooks can be gated before execution."),
                PlatformCapability("execution_interception", "native", "Command planning and agent execution can be reviewed before completion."),
                PlatformCapability("shell_guard", "native", "Shell execution paths can be blocked or logged via policy enforcement."),
                PlatformCapability("file_guard", "native", "Workspace file access can be reviewed for sensitive or high-risk writes."),
                PlatformCapability("network_guard", "partial", "External network calls are partially controllable through local policy wrappers."),
                PlatformCapability("review_queue", "native", "Risky actions can be staged for human approval workflows."),
                PlatformCapability("telemetry", "native", "Cursor events can be emitted to telemetry sinks and logs."),
                PlatformCapability("policy_sync", "native", "Policies can be pushed into the local Cursor workflow environment."),
                PlatformCapability("audit_export", "native", "Decision and action trails can be exported to the audit record store."),
            ],
            metadata={
                "adapter": "app.adapters.generic_agent_adapter",
                "priority": 3,
            },
        ),
        PlatformProfile(
            platform="goose",
            display_name="Goose",
            install_mode="one-command-local",
            capabilities=[
                PlatformCapability("prompt_interception", "native", "Goose prompt lifecycle can be inspected and filtered in-process."),
                PlatformCapability("tool_interception", "native", "Tool calls can be intercepted and evaluated before execution."),
                PlatformCapability("execution_interception", "native", "Execution plans can be checked against policy before approval."),
                PlatformCapability("shell_guard", "native", "Shell and subprocess command execution can be restricted."),
                PlatformCapability("file_guard", "native", "File reads and writes can be subject to guard policies."),
                PlatformCapability("network_guard", "partial", "External connectivity can be partially protected through host-level controls."),
                PlatformCapability("review_queue", "native", "High-risk actions can be queued for approval prior to execution."),
                PlatformCapability("telemetry", "native", "Goose runtime telemetry can be captured and forwarded."),
                PlatformCapability("policy_sync", "native", "Runtime policy states can be synchronized to Goose workflows."),
                PlatformCapability("audit_export", "native", "Security decisions can be exported to the centralized audit stream."),
            ],
            metadata={
                "adapter": "app.adapters.generic_agent_adapter",
                "priority": 4,
            },
        ),
        PlatformProfile(
            platform="gemini-cli",
            display_name="Gemini CLI",
            install_mode="one-command-local",
            capabilities=[
                PlatformCapability("prompt_interception", "native", "Gemini CLI prompt payloads can be intercepted before execution."),
                PlatformCapability("tool_interception", "native", "Tool calls can be evaluated and filtered according to policy."),
                PlatformCapability("execution_interception", "native", "Command plans and execution states can be reviewed before completion."),
                PlatformCapability("shell_guard", "native", "CLI shell operations can be monitored and restricted."),
                PlatformCapability("file_guard", "native", "File system operations can be reviewed and constrained."),
                PlatformCapability("network_guard", "partial", "Outbound requests can be partially restricted through local policy wrappers."),
                PlatformCapability("review_queue", "native", "Risky actions can await human approval or policy hold states."),
                PlatformCapability("telemetry", "native", "Gemini CLI session telemetry can be emitted to IronClaw."),
                PlatformCapability("policy_sync", "native", "Policy bundles can be synchronized into the CLI runtime."),
                PlatformCapability("audit_export", "native", "Audit-safe export of tool decisions and command execution flows is supported."),
            ],
            metadata={
                "adapter": "app.adapters.generic_agent_adapter",
                "priority": 5,
            },
        ),
        PlatformProfile(
            platform="copilot",
            display_name="GitHub Copilot",
            install_mode="one-command-local",
            capabilities=[
                PlatformCapability("prompt_interception", "native", "Copilot prompt payloads can be introspected and approved before dispatch."),
                PlatformCapability("tool_interception", "native", "Repository and coding tool calls can be guarded before execution."),
                PlatformCapability("execution_interception", "native", "Command and patch execution plans can be validated before completion."),
                PlatformCapability("shell_guard", "native", "Shell operations can be gated during AI-assisted coding tasks."),
                PlatformCapability("file_guard", "native", "Repository file reads and writes can be mediated and constrained."),
                PlatformCapability("network_guard", "partial", "Networked operations are partially controlled through local host policy enforcement."),
                PlatformCapability("review_queue", "native", "Sensitive file changes and tool activity can be queued for review."),
                PlatformCapability("telemetry", "native", "Copilot actions and guard events can be forwarded to IronClaw telemetry."),
                PlatformCapability("policy_sync", "native", "Repository and agent policies can be synchronized to Copilot sessions."),
                PlatformCapability("audit_export", "native", "Copilot command and patch decisions can be exported to audit records."),
            ],
            metadata={
                "adapter": "app.adapters.generic_agent_adapter",
                "priority": 6,
            },
        ),
        PlatformProfile(
            platform="security-guardian",
            display_name="Security Guardian Skills",
            install_mode="one-command-local",
            capabilities=[
                PlatformCapability("prompt_interception", "native", "Security prompts and policy bundles can be intercepted and validated."),
                PlatformCapability("tool_interception", "native", "Shared security tooling and skill triggers can be guarded."),
                PlatformCapability("execution_interception", "native", "Security automation and command execution can be evaluated before release."),
                PlatformCapability("shell_guard", "native", "Shell activity used by security tooling can be restricted and monitored."),
                PlatformCapability("file_guard", "native", "Sensitive security artifacts can be protected against writes and tampering."),
                PlatformCapability("network_guard", "native", "Security workflows can enforce network access controls to trusted destinations."),
                PlatformCapability("review_queue", "native", "High-risk security actions can be escalated to review queues."),
                PlatformCapability("telemetry", "native", "Security telemetry can be aggregated across the shared guard package."),
                PlatformCapability("policy_sync", "native", "Security policy bundles can be synced across all supported runtimes."),
                PlatformCapability("audit_export", "native", "Security decisions can be exported for regulatory and forensic auditing."),
            ],
            metadata={
                "adapter": "app.adapters.generic_agent_adapter",
                "priority": 7,
            },
        ),
        PlatformProfile(
            platform="hermes",
            display_name="Hermes",
            install_mode="one-command-local",
            capabilities=[
                PlatformCapability("prompt_interception", "native", "Hermes prompt payloads can be inspected and filtered before execution."),
                PlatformCapability("tool_interception", "native", "Hermes tool and workflow dispatches can be intercepted before action."),
                PlatformCapability("execution_interception", "native", "Hermes workflow plans and high-risk step execution can be reviewed before completion."),
                PlatformCapability("shell_guard", "native", "Hermes shell and subprocess operations can be blocked or logged by policy."),
                PlatformCapability("file_guard", "native", "Hermes workspace file reads and writes can be mediated with guard rules."),
                PlatformCapability("network_guard", "partial", "External network calls are partially controlled through host-side policy enforcement."),
                PlatformCapability("review_queue", "native", "Risky Hermes actions can be staged for approval or human review."),
                PlatformCapability("telemetry", "native", "Hermes execution and policy telemetry can be forwarded to the control plane."),
                PlatformCapability("policy_sync", "native", "Hermes policy bundles can be synchronized into the local runtime environment."),
                PlatformCapability("audit_export", "native", "Hermes activity and decision trails can be exported to the audit record store."),
            ],
            metadata={
                "adapter": "app.adapters.hermes_adapter",
                "priority": 8,
            },
        ),
        PlatformProfile(
            platform="generic-agent",
            display_name="Generic Agent Runtime",
            install_mode="api-attachment",
            capabilities=[
                PlatformCapability("prompt_interception", "partial", "Requires host runtime hook support to inspect prompts."),
                PlatformCapability("tool_interception", "partial", "Requires wrapper-based interception at the host boundary."),
                PlatformCapability("execution_interception", "partial", "Depends on the platform's execution contract and hook depth."),
                PlatformCapability("shell_guard", "partial", "Limited to host-side control when a shell bridge is available."),
                PlatformCapability("file_guard", "partial", "File handling is only protected when the runtime exposes file hooks."),
                PlatformCapability("network_guard", "partial", "Network controls depend on runtime or host network mediation."),
                PlatformCapability("review_queue", "partial", "Review gating can be attached via policy responses when supported."),
                PlatformCapability("telemetry", "native", "Telemetry can be sent through API contracts and logs."),
                PlatformCapability("policy_sync", "partial", "Policy sync is possible when the runtime supports policy transport."),
                PlatformCapability("audit_export", "native", "Audit events can be exported through the control plane contract."),
            ],
            metadata={
                "adapter": "app.adapters.generic_agent_adapter",
                "priority": 9,
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
