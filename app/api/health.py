from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.settings import get_settings
from app.dependencies.action_execute import get_action_execute_pipeline
from app.orchestrator.secure_runtime_pipeline import (
    get_secure_runtime_health_snapshot,
)
from app.services.prompt_guard import resolve_prompt_guard_path
from app.services.sandbox_broker_client import SandboxBrokerClient

router = APIRouter(prefix="/health/details", tags=["health"])

SERVICE_NAME = "IronClaw-Security"
SERVICE_VERSION = "1.0.0"
HEALTH_PURPOSE = "compact-readiness"
OK_STATUSES = frozenset({"ok", "healthy"})
WARN_STATUSES = frozenset({"warn", "warning", "degraded"})


class HealthStatus(StrEnum):
    ok = "ok"
    warn = "warn"
    degraded = "degraded"
    error = "error"
    unknown = "unknown"


class ComponentHealth(BaseModel):
    name: str
    status: HealthStatus
    details: dict[str, Any] = Field(default_factory=dict)


class HealthSnapshot(BaseModel):
    status: HealthStatus
    service: str
    timestamp: str
    version: str
    components: list[ComponentHealth] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_component_status(raw_status: Any) -> HealthStatus:
    value = str(raw_status or "").strip().lower()
    if value in OK_STATUSES:
        return HealthStatus.ok
    if value in WARN_STATUSES:
        return HealthStatus.warn
    if value == HealthStatus.error.value:
        return HealthStatus.error
    return HealthStatus.unknown


def _resolve_overall_status(components: list[ComponentHealth]) -> HealthStatus:
    if any(component.status == HealthStatus.error for component in components):
        return HealthStatus.degraded
    if any(component.status == HealthStatus.unknown for component in components):
        return HealthStatus.degraded
    if any(component.status == HealthStatus.degraded for component in components):
        return HealthStatus.degraded
    if any(component.status == HealthStatus.warn for component in components):
        return HealthStatus.warn
    return HealthStatus.ok


def _build_api_component() -> ComponentHealth:
    return ComponentHealth(
        name="api",
        status=HealthStatus.ok,
        details={"reachable": True},
    )


def _build_secure_runtime_component() -> ComponentHealth:
    try:
        pipeline = get_action_execute_pipeline()
        pipeline_health = get_secure_runtime_health_snapshot(pipeline)

        if not isinstance(pipeline_health, dict):
            return ComponentHealth(
                name="secure_runtime_pipeline",
                status=HealthStatus.unknown,
                details={
                    "error": "invalid-health-payload",
                    "observed_type": type(pipeline_health).__name__,
                },
            )

        normalized_status = _normalize_component_status(pipeline_health.get("status"))
        return ComponentHealth(
            name="secure_runtime_pipeline",
            status=normalized_status,
            details=pipeline_health,
        )
    except Exception as exc:
        return ComponentHealth(
            name="secure_runtime_pipeline",
            status=HealthStatus.error,
            details={"error": repr(exc)},
        )


def _build_return_gate_component() -> ComponentHealth:
    try:
        broker = SandboxBrokerClient().health()
    except Exception as exc:
        return ComponentHealth(
            name="return_gate",
            status=HealthStatus.error,
            details={"error": repr(exc)},
        )

    if broker.get("reachable"):
        scanner_image = broker.get("scanner_image", "unknown")
        if scanner_image == "ready":
            return ComponentHealth(name="return_gate", status=HealthStatus.ok, details={"broker": "reachable"})
        return ComponentHealth(
            name="return_gate",
            status=HealthStatus.degraded,
            details={"broker": "reachable", "scanner_image": scanner_image, "reason": "scanner_image_not_ready"},
        )
    return ComponentHealth(
        name="return_gate",
        status=HealthStatus.degraded,
        details={"broker": "unavailable", "reason": broker.get("reason")},
    )


def _build_install_gate_component() -> ComponentHealth:
    return ComponentHealth(
        name="install_gate",
        status=HealthStatus.ok,
        details={"policy": "scan-and-allow", "pinned_sources": "install_allowlist", "third_party_scan": "sandbox_broker"},
    )


def _build_prompt_guard_component() -> ComponentHealth:
    settings = get_settings()
    model_path = resolve_prompt_guard_path(settings.guard_model_path)
    model_files_present = model_path.is_dir() and (model_path / "config.json").is_file() and (model_path / "model.safetensors").is_file()
    details: dict[str, Any] = {"enabled": settings.guard_enabled, "model_files_present": model_files_present}
    if not settings.guard_enabled:
        return ComponentHealth(
            name="prompt_guard",
            status=HealthStatus.warn,
            details={**details, "reason": "prompt_guard_disabled"},
        )
    if not model_files_present:
        return ComponentHealth(
            name="prompt_guard",
            status=HealthStatus.degraded,
            details={**details, "reason": "prompt_guard_model_missing"},
        )
    return ComponentHealth(name="prompt_guard", status=HealthStatus.ok, details=details)


@router.get("", response_model=HealthSnapshot)
def read_compact_health() -> HealthSnapshot:
    """Authenticated compact health snapshot for operational dashboards.

    Served at /health/details behind the protected dependencies in app.main.
    The public /health, /health/liveness, and /health/readiness routes are
    defined in app.main and must not be shadowed by this router.
    """
    components = [
        _build_api_component(),
        _build_secure_runtime_component(),
        _build_return_gate_component(),
        _build_install_gate_component(),
        _build_prompt_guard_component(),
    ]
    overall_status = _resolve_overall_status(components)

    return HealthSnapshot(
        status=overall_status,
        service=SERVICE_NAME,
        timestamp=_utc_now_iso(),
        version=SERVICE_VERSION,
        components=components,
        metadata={
            "purpose": HEALTH_PURPOSE,
            "notes": [
                "This snapshot is authenticated; use the public /health routes for uptime monitoring.",
                "The secure_runtime_pipeline details field is intentionally compact and stable.",
            ],
            "component_count": len(components),
        },
    )
