from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled", "healthy", "ready"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled", "unhealthy", "not_ready"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_datetime(value: Any, default: datetime | None = None) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default
        candidate = candidate.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return default
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return default


def _derive_health(ready: bool, degraded: bool, incident_count: int) -> str:
    if not ready:
        return "down"
    if degraded or incident_count > 0:
        return "degraded"
    return "healthy"


@dataclass(frozen=True, slots=True)
class RuntimeStatus:
    service: str = "ironclaw-security"
    environment: str = "local"
    version: str = "dev"
    runtime_id: str = "primary"
    health: str = "healthy"
    ready: bool = True
    degraded: bool = False
    enforcement_mode: str = "enforce"
    sandbox_available: bool = True
    policy_engine_loaded: bool = True
    telemetry_pipeline_ready: bool = True
    review_queue_available: bool = True
    active_sessions: int = 0
    queued_reviews: int = 0
    quarantined_items: int = 0
    open_incidents: int = 0
    uptime_seconds: int = 0
    started_at: datetime = field(default_factory=_utc_now)
    checked_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "environment": self.environment,
            "version": self.version,
            "runtime_id": self.runtime_id,
            "health": self.health,
            "ready": self.ready,
            "degraded": self.degraded,
            "enforcement_mode": self.enforcement_mode,
            "sandbox_available": self.sandbox_available,
            "policy_engine_loaded": self.policy_engine_loaded,
            "telemetry_pipeline_ready": self.telemetry_pipeline_ready,
            "review_queue_available": self.review_queue_available,
            "active_sessions": self.active_sessions,
            "queued_reviews": self.queued_reviews,
            "quarantined_items": self.quarantined_items,
            "open_incidents": self.open_incidents,
            "uptime_seconds": self.uptime_seconds,
            "started_at": _isoformat(self.started_at),
            "checked_at": _isoformat(self.checked_at),
        }


def default_runtime_status() -> RuntimeStatus:
    return RuntimeStatus()


def build_runtime_status(
    data: dict[str, Any] | None = None,
    *,
    baseline: RuntimeStatus | None = None,
) -> RuntimeStatus:
    source = data or {}
    current = baseline or default_runtime_status()

    ready = _coerce_bool(source.get("ready"), current.ready)
    degraded = _coerce_bool(source.get("degraded"), current.degraded)
    open_incidents = _coerce_int(source.get("open_incidents"), current.open_incidents)

    health = _coerce_str(source.get("health"))
    if not health:
        health = _derive_health(ready=ready, degraded=degraded, incident_count=open_incidents)

    started_at = _coerce_datetime(source.get("started_at"), current.started_at) or _utc_now()
    checked_at = _coerce_datetime(source.get("checked_at"), _utc_now()) or _utc_now()

    return RuntimeStatus(
        service=_coerce_str(source.get("service"), current.service) or current.service,
        environment=_coerce_str(source.get("environment"), current.environment) or current.environment,
        version=_coerce_str(source.get("version"), current.version) or current.version,
        runtime_id=_coerce_str(source.get("runtime_id"), current.runtime_id) or current.runtime_id,
        health=health,
        ready=ready,
        degraded=degraded,
        enforcement_mode=_coerce_str(source.get("enforcement_mode"), current.enforcement_mode) or current.enforcement_mode,
        sandbox_available=_coerce_bool(source.get("sandbox_available"), current.sandbox_available),
        policy_engine_loaded=_coerce_bool(source.get("policy_engine_loaded"), current.policy_engine_loaded),
        telemetry_pipeline_ready=_coerce_bool(source.get("telemetry_pipeline_ready"), current.telemetry_pipeline_ready),
        review_queue_available=_coerce_bool(source.get("review_queue_available"), current.review_queue_available),
        active_sessions=max(0, _coerce_int(source.get("active_sessions"), current.active_sessions)),
        queued_reviews=max(0, _coerce_int(source.get("queued_reviews"), current.queued_reviews)),
        quarantined_items=max(0, _coerce_int(source.get("quarantined_items"), current.quarantined_items)),
        open_incidents=max(0, open_incidents),
        uptime_seconds=max(0, _coerce_int(source.get("uptime_seconds"), current.uptime_seconds)),
        started_at=started_at,
        checked_at=checked_at,
    )


def runtime_status_summary(status: RuntimeStatus) -> dict[str, Any]:
    control_plane_ready = all(
        (
            status.ready,
            status.sandbox_available,
            status.policy_engine_loaded,
            status.telemetry_pipeline_ready,
            status.review_queue_available,
        )
    )

    return {
        "service": status.service,
        "runtime_id": status.runtime_id,
        "environment": status.environment,
        "version": status.version,
        "health": status.health,
        "ready": status.ready,
        "degraded": status.degraded,
        "control_plane_ready": control_plane_ready,
        "enforcement_mode": status.enforcement_mode,
        "capabilities": {
            "sandbox_available": status.sandbox_available,
            "policy_engine_loaded": status.policy_engine_loaded,
            "telemetry_pipeline_ready": status.telemetry_pipeline_ready,
            "review_queue_available": status.review_queue_available,
        },
        "load": {
            "active_sessions": status.active_sessions,
            "queued_reviews": status.queued_reviews,
            "quarantined_items": status.quarantined_items,
            "open_incidents": status.open_incidents,
        },
        "timing": {
            "uptime_seconds": status.uptime_seconds,
            "started_at": _isoformat(status.started_at),
            "checked_at": _isoformat(status.checked_at),
        },
    }