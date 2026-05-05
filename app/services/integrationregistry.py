from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal


IntegrationStatus = Literal[
    "planned",
    "available",
    "configured",
    "verifying",
    "ready",
    "degraded",
    "disabled",
]

CapabilityName = Literal[
    "prompt_guard",
    "tool_guard",
    "execution_control",
    "review_queue",
    "telemetry",
    "policy_bundle",
    "secrets_redaction",
    "groq_assist",
]


@dataclass(slots=True)
class IntegrationCapability:
    name: CapabilityName
    enabled: bool = True
    maturity: str = "gen1"
    notes: str = ""


@dataclass(slots=True)
class IntegrationRecord:
    integrationid: str
    platform: str
    displayname: str
    status: IntegrationStatus
    description: str
    version: str
    adaptermodule: str
    verificationroute: str
    settingsroute: str
    manifestroute: str
    installedat: str | None = None
    verifiedat: str | None = None
    tags: list[str] = field(default_factory=list)
    capabilities: list[IntegrationCapability] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _base_capabilities() -> list[IntegrationCapability]:
    return [
        IntegrationCapability(name="prompt_guard", enabled=True, maturity="gen1"),
        IntegrationCapability(name="tool_guard", enabled=True, maturity="gen1"),
        IntegrationCapability(name="execution_control", enabled=True, maturity="gen1"),
        IntegrationCapability(name="review_queue", enabled=True, maturity="gen1"),
        IntegrationCapability(name="telemetry", enabled=True, maturity="gen1"),
        IntegrationCapability(name="policy_bundle", enabled=True, maturity="gen1"),
        IntegrationCapability(name="secrets_redaction", enabled=True, maturity="gen1"),
    ]


class IntegrationRegistry:
    def __init__(self) -> None:
        self._records: dict[str, IntegrationRecord] = {}
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        seeded_at = _utc_now()

        self._records = {
            "integration-claude-code": IntegrationRecord(
                integrationid="integration-claude-code",
                platform="claude",
                displayname="Claude Code",
                status="available",
                description=(
                    "IronClaw control-plane adapter for Claude and Claude Code "
                    "security enforcement."
                ),
                version="gen1",
                adaptermodule="app.claudeguardrouter",
                verificationroute="/integrations/integration-claude-code/verify",
                settingsroute="/ui/integrations/settings",
                manifestroute="/integrations/integration-claude-code/manifest",
                installedat=seeded_at,
                verifiedat=None,
                tags=["anthropic", "claude-code", "agents"],
                capabilities=_base_capabilities(),
                metadata={
                    "provider": "anthropic",
                    "runtime": "router",
                    "defaultpolicy": "strict",
                    "slug": "claude-code",
                },
            ),
            "integration-openclaw": IntegrationRecord(
                integrationid="integration-openclaw",
                platform="openclaw",
                displayname="OpenClaw",
                status="ready",
                description=(
                    "Native IronClaw enforcement integration for OpenClaw-style "
                    "agent toolchains."
                ),
                version="gen1",
                adaptermodule="app.adapters.openclaw",
                verificationroute="/integrations/integration-openclaw/verify",
                settingsroute="/ui/integrations/settings",
                manifestroute="/integrations/integration-openclaw/manifest",
                installedat=seeded_at,
                verifiedat=seeded_at,
                tags=["agent-framework", "tooling", "sandbox"],
                capabilities=_base_capabilities(),
                metadata={
                    "provider": "openclaw",
                    "runtime": "local",
                    "defaultpolicy": "strict",
                    "slug": "openclaw",
                },
            ),
            "integration-generic-agent": IntegrationRecord(
                integrationid="integration-generic-agent",
                platform="generic",
                displayname="Generic Agent Runtime",
                status="planned",
                description=(
                    "Generic IronClaw adapter template for custom agent runtimes "
                    "and toolchains."
                ),
                version="gen1",
                adaptermodule="app.adapters.genericagent",
                verificationroute="/integrations/integration-generic-agent/verify",
                settingsroute="/ui/integrations/settings",
                manifestroute="/integrations/integration-generic-agent/manifest",
                installedat=None,
                verifiedat=None,
                tags=["agents", "template"],
                capabilities=_base_capabilities(),
                metadata={
                    "provider": "generic",
                    "runtime": "template",
                    "defaultpolicy": "strict",
                    "slug": "generic-agent",
                },
            ),
            "integration-groq": IntegrationRecord(
                integrationid="integration-groq",
                platform="groq",
                displayname="Groq Assist",
                status="configured",
                description="IronClaw adapter for Groq inference and secured runtime routing.",
                version="gen1",
                adaptermodule="app.services.groqclient",
                verificationroute="/integrations/integration-groq/verify",
                settingsroute="/ui/integrations/settings",
                manifestroute="/integrations/integration-groq/manifest",
                installedat=seeded_at,
                verifiedat=None,
                tags=["llm", "inference", "runtime"],
                capabilities=_base_capabilities()
                + [
                    IntegrationCapability(
                        name="groq_assist",
                        enabled=True,
                        maturity="gen1",
                        notes="Groq Assist-specific capabilities.",
                    )
                ],
                metadata={
                    "provider": "groq",
                    "runtime": "api",
                    "defaultpolicy": "strict",
                    "slug": "groq-assist",
                },
            ),
        }

    def list_integrations(self) -> list[IntegrationRecord]:
        return sorted(self._records.values(), key=lambda record: record.integrationid)

    def get_integration(self, integrationid: str) -> IntegrationRecord | None:
        return self._records.get(integrationid.strip().lower())

    def has_integration(self, integrationid: str) -> bool:
        return self.get_integration(integrationid) is not None

    def register_integration(self, record: IntegrationRecord) -> IntegrationRecord:
        normalized_id = record.integrationid.strip().lower()
        stored = IntegrationRecord(
            integrationid=normalized_id,
            platform=record.platform.strip().lower(),
            displayname=record.displayname.strip(),
            status=record.status,
            description=record.description.strip(),
            version=record.version.strip(),
            adaptermodule=record.adaptermodule.strip(),
            verificationroute=record.verificationroute.strip(),
            settingsroute=record.settingsroute.strip(),
            manifestroute=record.manifestroute.strip(),
            installedat=record.installedat,
            verifiedat=record.verifiedat,
            tags=[tag.strip().lower() for tag in record.tags if tag.strip()],
            capabilities=[
                IntegrationCapability(
                    name=capability.name,
                    enabled=capability.enabled,
                    maturity=capability.maturity.strip(),
                    notes=capability.notes.strip(),
                )
                for capability in record.capabilities
            ],
            metadata={
                str(key).strip(): str(value).strip()
                for key, value in record.metadata.items()
                if str(key).strip()
            },
        )
        self._records[normalized_id] = stored
        return stored

    def update_status(
        self,
        integrationid: str,
        status: IntegrationStatus,
        *,
        verified: bool = False,
    ) -> IntegrationRecord | None:
        record = self.get_integration(integrationid)
        if record is None:
            return None

        record.status = status
        if verified:
            record.verifiedat = _utc_now()
        return record

    def mark_verified(self, integrationid: str) -> IntegrationRecord | None:
        return self.update_status(integrationid, "ready", verified=True)

    def install_integration(self, integrationid: str) -> IntegrationRecord | None:
        record = self.get_integration(integrationid)
        if record is None:
            return None

        record.installedat = record.installedat or _utc_now()
        if record.status == "planned":
            record.status = "available"
        return record

    def integration_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {
            "total_integrations": len(self._records),
            "planned": 0,
            "available": 0,
            "configured": 0,
            "verifying": 0,
            "ready": 0,
            "degraded": 0,
            "disabled": 0,
        }
        for record in self._records.values():
            summary[record.status] += 1
        return summary


_registry = IntegrationRegistry()


def get_integration_registry() -> IntegrationRegistry:
    return _registry