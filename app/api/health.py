from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.dependencies.action_execute import get_action_execute_pipeline
from app.orchestrator.secure_runtime_pipeline import (
    get_secure_runtime_health_snapshot,
)

router = APIRouter(prefix="/health", tags=["health"])

SERVICE_NAME = "IronClaw-Security"
SERVICE_VERSION = "1.0.0"
HEALTH_PURPOSE = "compact-readiness"
OK_STATUSES = frozenset({"ok", "healthy"})
WARN_STATUSES = frozenset({"warn", "warning", "degraded"})


class HealthStatus(str, Enum):
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


@router.get("", response_model=HealthSnapshot)
def read_compact_health() -> HealthSnapshot:
    """
    Compact health snapshot for readiness and operational dashboards.

    This endpoint is designed to be:
    - Lightweight enough for frequent polling (readiness / uptime checks),
    - Structured enough to power the UI health snapshot panel,
    - Stable as a public contract for external monitoring tools.
    """
    components = [
        _build_api_component(),
        _build_secure_runtime_component(),
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
                "This snapshot is safe for external uptime monitoring.",
                "The secure_runtime_pipeline details field is intentionally compact and stable.",
            ],
            "component_count": len(components),
        },
    )