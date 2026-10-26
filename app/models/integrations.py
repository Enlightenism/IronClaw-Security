from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IntegrationStatus(StrEnum):
    PLANNED = "planned"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class IntegrationType(StrEnum):
    NATIVE = "native"
    ADAPTER = "adapter"
    CLI = "cli"
    REMOTE = "remote"


class CapabilityName(StrEnum):
    PROMPT_INTERCEPTION = "prompt_interception"
    TOOL_INTERCEPTION = "tool_interception"
    EXECUTION_INTERCEPTION = "execution_interception"
    FILE_GUARD = "file_guard"
    SHELL_GUARD = "shell_guard"
    NETWORK_GUARD = "network_guard"
    GIT_GUARD = "git_guard"
    REVIEW_QUEUE = "review_queue"
    AUDIT_EXPORT = "audit_export"
    POLICY_SYNC = "policy_sync"
    TELEMETRY = "telemetry"
    GUARD_ASSIST = "guard_assist"


class VerificationState(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class PlatformCapabilitySupport(StrEnum):
    NATIVE = "native"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class IntegrationBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        use_enum_values=True,
    )


class IntegrationCapabilityResponse(IntegrationBaseModel):
    name: CapabilityName
    enabled: bool = True
    details: str | None = None


class IntegrationRecordResponse(IntegrationBaseModel):
    integration_id: str
    name: str
    slug: str
    platform: str
    integration_type: IntegrationType
    status: IntegrationStatus
    version: str
    command_name: str | None = None
    description: str = ""
    entrypoint: str | None = None
    install_target: str | None = None
    capabilities: list[IntegrationCapabilityResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)


class IntegrationRegistryResponse(IntegrationBaseModel):
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    total: int = 0
    items: list[IntegrationRecordResponse] = Field(default_factory=list)


class IntegrationRegistrySummaryResponse(IntegrationBaseModel):
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    total_integrations: int = 0
    active_integrations: int = 0
    planned_integrations: int = 0
    disabled_integrations: int = 0
    deprecated_integrations: int = 0
    platforms: dict[str, int] = Field(default_factory=dict)
    capabilities: dict[str, int] = Field(default_factory=dict)
    one_command_ready_targets: list[str] = Field(default_factory=list)


class IntegrationStatusUpdateRequest(IntegrationBaseModel):
    status: IntegrationStatus


class IntegrationFilterRequest(IntegrationBaseModel):
    status: IntegrationStatus | None = None
    platform: str | None = Field(default=None, min_length=1)
    capability: CapabilityName | None = None


class VerificationCheckResponse(IntegrationBaseModel):
    name: str
    state: VerificationState
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationVerificationResponse(IntegrationBaseModel):
    integration_id: str
    slug: str
    platform: str
    status: str
    verified: bool
    checked_at: str = Field(default_factory=utc_now_iso)
    checks: list[VerificationCheckResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationVerificationSummaryResponse(IntegrationBaseModel):
    integration_id: str
    slug: str
    platform: str
    status: str
    verified: bool
    pass_count: int = 0
    warn_count: int = 0
    fail_count: int = 0
    checked_at: str = Field(default_factory=utc_now_iso)


class AdapterManifestResponse(IntegrationBaseModel):
    manifest_version: str
    generated_at: str = Field(default_factory=utc_now_iso)
    integration_id: str
    slug: str
    platform: str
    name: str
    version: str
    command_name: str | None = None
    entrypoint: str | None = None
    install_target: str | None = None
    capabilities: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdapterManifestSummaryResponse(IntegrationBaseModel):
    manifest_version: str
    integration_id: str
    slug: str
    platform: str
    version: str
    capability_count: int = 0
    generated_at: str = Field(default_factory=utc_now_iso)


class PlatformCapabilityResponse(IntegrationBaseModel):
    name: str
    support: PlatformCapabilitySupport
    details: str = ""


class PlatformProfileResponse(IntegrationBaseModel):
    platform: str
    display_name: str
    install_mode: str
    capabilities: list[PlatformCapabilityResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    checked_at: str = Field(default_factory=utc_now_iso)


class PlatformProfileSummaryResponse(IntegrationBaseModel):
    platform: str
    display_name: str
    install_mode: str
    capability_count: int = 0
    native_capabilities: int = 0
    partial_capabilities: int = 0
    unsupported_capabilities: int = 0
    checked_at: str = Field(default_factory=utc_now_iso)


class PolicyBundleVerificationStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    UNSIGNED = "unsigned"


class PolicyBundleResponse(IntegrationBaseModel):
    bundle_id: str
    version: str
    created_at: str = Field(default_factory=utc_now_iso)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SignedPolicyBundleResponse(IntegrationBaseModel):
    bundle: PolicyBundleResponse
    signature: str
    key_id: str
    algorithm: str = "hs256"
    signed_at: str = Field(default_factory=utc_now_iso)


class PolicyBundleVerificationResponse(IntegrationBaseModel):
    bundle_id: str
    version: str
    status: PolicyBundleVerificationStatus
    reason: str
    key_id: str | None = None
    algorithm: str | None = None
    verified_at: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SignedPolicyBundleSummaryResponse(IntegrationBaseModel):
    bundle_id: str
    version: str
    policy_count: int = 0
    key_id: str
    algorithm: str = "hs256"
    signed_at: str = Field(default_factory=utc_now_iso)
    verification_status: PolicyBundleVerificationStatus = PolicyBundleVerificationStatus.UNSIGNED
    verification_reason: str = "not verified"
