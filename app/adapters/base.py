from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from app.services.adapter_manifest import AdapterManifest, build_adapter_manifest
from app.services.integration_registry import IntegrationRecord

AdapterHealth = Literal["ready", "degraded", "offline"]
AdapterExecutionStatus = Literal[
    "accepted",
    "accepted_with_warnings",
    "guarded",
    "blocked",
    "offline",
    "failed",
]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _clean_dict(value: dict[str, Any] | None) -> dict[str, Any]:
    return dict(value or {})


def _clean_list_of_dicts(value: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not value:
        return []
    return [dict(item) for item in value]


def _require_text(value: str | None, field_name: str) -> str:
    normalized = _normalize_text(value)
    if not normalized:
        raise ValueError(f"{field_name} is required")
    return normalized


@dataclass(slots=True)
class AdapterHandshake:
    adapter_slug: str
    platform: str
    protocol_version: str
    status: AdapterHealth
    connected_at: str
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.adapter_slug = _require_text(self.adapter_slug, "adapter_slug")
        self.platform = _require_text(self.platform, "platform")
        self.protocol_version = _require_text(self.protocol_version, "protocol_version")
        self.connected_at = _require_text(self.connected_at, "connected_at")
        self.capabilities = _clean_list_of_dicts(self.capabilities)
        self.metadata = _clean_dict(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_slug": self.adapter_slug,
            "platform": self.platform,
            "protocol_version": self.protocol_version,
            "status": self.status,
            "connected_at": self.connected_at,
            "capabilities": [dict(capability) for capability in self.capabilities],
            "metadata": dict(self.metadata),
        }

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(slots=True)
class AdapterExecutionRequest:
    action_type: str
    target: str
    payload: dict[str, Any] = field(default_factory=dict)
    requested_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.action_type = _require_text(self.action_type, "action_type")
        self.target = _require_text(self.target, "target")
        self.payload = _clean_dict(self.payload)
        self.requested_at = _require_text(self.requested_at, "requested_at")
        self.metadata = _clean_dict(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "payload": dict(self.payload),
            "requested_at": self.requested_at,
            "metadata": dict(self.metadata),
        }

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(slots=True)
class AdapterExecutionResult:
    adapter_slug: str
    platform: str
    success: bool
    status: AdapterExecutionStatus
    summary: str
    completed_at: str
    output: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.adapter_slug = _require_text(self.adapter_slug, "adapter_slug")
        self.platform = _require_text(self.platform, "platform")
        self.summary = _require_text(self.summary, "summary")
        self.completed_at = _require_text(self.completed_at, "completed_at")
        self.output = _clean_dict(self.output)
        self.metadata = _clean_dict(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_slug": self.adapter_slug,
            "platform": self.platform,
            "success": self.success,
            "status": self.status,
            "summary": self.summary,
            "completed_at": self.completed_at,
            "output": dict(self.output),
            "metadata": dict(self.metadata),
        }

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


class SupportsAdapter(Protocol):
    record: IntegrationRecord

    def handshake(self) -> AdapterHandshake: ...
    def manifest(self) -> AdapterManifest: ...
    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult: ...


@dataclass(slots=True)
class BaseIntegrationAdapter:
    record: IntegrationRecord
    protocol_version: str = "1.0.0"
    health: AdapterHealth = "ready"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.protocol_version = _require_text(self.protocol_version, "protocol_version")
        self.metadata = _clean_dict(self.metadata)

    @property
    def adapter_slug(self) -> str:
        return self.record.slug

    @property
    def platform(self) -> str:
        return self.record.platform

    def base_metadata(self) -> dict[str, Any]:
        return {
            "integration_id": self.record.integration_id,
            "integration_type": self.record.integration_type,
            "integration_status": self.record.status,
            "protocol_version": self.protocol_version,
            "adapter_health": self.health,
            **self.metadata,
        }

    def is_available(self) -> bool:
        return self.health != "offline"

    def supported_action_types(self) -> list[str]:
        return []

    def handshake(self) -> AdapterHandshake:
        return AdapterHandshake(
            adapter_slug=self.adapter_slug,
            platform=self.platform,
            protocol_version=self.protocol_version,
            status=self.health,
            connected_at=_utc_now(),
            capabilities=[capability.to_dict() for capability in self.record.capabilities],
            metadata=self.base_metadata(),
        )

    def manifest(self) -> AdapterManifest:
        return build_adapter_manifest(
            self.record,
            extra_metadata={
                **self.base_metadata(),
                "supported_action_types": self.supported_action_types(),
            },
        )

    def validate_request(self, request: AdapterExecutionRequest) -> None:
        supported = self.supported_action_types()
        if supported and request.action_type not in supported:
            raise ValueError(
                f"unsupported action_type '{request.action_type}' for adapter '{self.adapter_slug}'",
            )

    # Alias used by registry-wired adapter subclasses (e.g. ClaudeCodeAdapter)
    def from_base_validate(self, request: AdapterExecutionRequest) -> None:
        return self.validate_request(request)

    def build_result(
        self,
        *,
        request: AdapterExecutionRequest,
        success: bool,
        status: AdapterExecutionStatus,
        summary: str,
        output: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AdapterExecutionResult:
        result_output = {
            "request": request.to_dict(),
            "integration_id": self.record.integration_id,
            **_clean_dict(output),
        }
        result_metadata = {
            **self.base_metadata(),
            **_clean_dict(metadata),
        }
        return AdapterExecutionResult(
            adapter_slug=self.adapter_slug,
            platform=self.platform,
            success=success,
            status=status,
            summary=summary,
            completed_at=_utc_now(),
            output=result_output,
            metadata=result_metadata,
        )

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        self.validate_request(request)

        if self.health == "offline":
            return self.build_result(
                request=request,
                success=False,
                status="offline",
                summary=f"{self.record.name} is offline and cannot execute '{request.action_type}'.",
            )

        status: AdapterExecutionStatus = "accepted" if self.health == "ready" else "accepted_with_warnings"
        summary = f"{self.record.name} accepted action '{request.action_type}' for target '{request.target}'." if self.health == "ready" else f"{self.record.name} accepted action '{request.action_type}' for target '{request.target}' in degraded mode."

        return self.build_result(
            request=request,
            success=True,
            status=status,
            summary=summary,
        )


def summarize_adapter_handshake(handshake: AdapterHandshake) -> dict[str, Any]:
    return {
        "adapter_slug": handshake.adapter_slug,
        "platform": handshake.platform,
        "protocol_version": handshake.protocol_version,
        "status": handshake.status,
        "capability_count": len(handshake.capabilities),
        "connected_at": handshake.connected_at,
    }


def summarize_adapter_execution(result: AdapterExecutionResult) -> dict[str, Any]:
    return {
        "adapter_slug": result.adapter_slug,
        "platform": result.platform,
        "success": result.success,
        "status": result.status,
        "completed_at": result.completed_at,
    }
